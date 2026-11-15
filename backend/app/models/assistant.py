"""The case-scoped assistant's persisted record: ``ai_conversations`` and ``ai_messages`` (§8.2).

Two tables, and the reason they exist is AI-04, which is a **mandatory** requirement: prompt,
retrieval context, model, version, temperature and token counts are logged for every interaction, so
that any answer can be reconstructed and challenged. A chat transcript kept only in the browser, or
only in a provider's logs, cannot be produced to a court six months later by this platform — and an
answer nobody can reproduce is an assertion, not evidence.

What these tables are *not*
---------------------------
``AI_ARCHITECTURE.md`` §10 draws a hard structural line between an assistant answer and a forensic
finding, and this module keeps it:

* **``ai_messages`` has no verification column.** Not "defaults to unverified" — the column does not
  exist, so no code path can set one. An examiner confirms ``analysis_results``; nothing confirms a
  chat answer, and a ``verification_status`` here would be a green tick waiting to be misread.
  ``tests/db/test_models.py`` asserts the absence, because a guarantee that lives only in a design
  document is one careless migration away from not existing.
* **No custody columns.** The assistant cannot alter custody records or delete anything (AI-03), so
  there is nothing here for it to sign.

Honesty constraints
-------------------
§8.2 states the rule plainly: "assistant messages with empty citations must set ``unsupported=true``
(AI-02)". That is a CHECK constraint, which means the assistant *cannot persist* an uncited claim
without declaring that the case data does not support it. The constraint is the feature; the
guardrail prompt is only the first line of defence, and a prompt can be bypassed by a model that
ignores it. A CHECK cannot.

Reproducibility columns
-----------------------
``model_name`` and ``model_version`` are a **snapshot**, per §8.2 — deliberately denormalised away
from ``ai_conversations.model_id``. A registry row is mutable (a model is deprecated, re-pinned,
retired) and the question "what produced this sentence" must be answerable from the message row
alone, years later, without joining to a table whose contents have since changed.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UTCDateTime
from app.db.uuid7 import uuid7
from app.models.enums import AIMessageStatus, ChatRole, native_enum

if TYPE_CHECKING:
    from app.models.cases import Case
    from app.models.identity import User
    from app.models.registry import AIModel

__all__ = ["AIConversation", "AIMessage"]

#: ``citations`` is JSONB, and §8.2 writes its constraint with ``cardinality(citations)`` — which
#: PostgreSQL does not have: ``cardinality`` takes an array, and the function does not exist for
#: ``jsonb`` (verified against PostgreSQL 16.2: ``function cardinality(jsonb) does not exist``). The
#: array-length equivalent for JSONB is ``jsonb_array_length``, and that is what the constraint below
#: uses. Recorded in ``migrations/README.md`` because it is a correction to the design's SQL, not a
#: change to the rule it states.
CITATION_COUNT = "jsonb_array_length(citations)"


class AIConversation(Base, TimestampMixin):
    """One assistant thread inside one case (§8.2, AI-01).

    ``case_id`` is NOT NULL because retrieval is hard-scoped to a case (AI_ARCHITECTURE §11.1: the
    ``case_id`` predicate is applied with a bound parameter and no retrieval function accepts it as an
    optional argument). A conversation with no case would be a channel to the model that is scoped to
    nothing, which is the one thing AI-01 forbids.

    ``provider`` is ``text`` with no CHECK, matching ``ai_provider_settings.provider``: §9 is explicit
    that a growing vocabulary must not be a native enum, and the two documents that name providers do
    not even agree on the spelling (``local_ollama``/``external_api`` in §8.2, ``ollama``/
    ``external:openai_compatible`` in AI_ARCHITECTURE §5). A CHECK would freeze one of those lists and
    make the other a migration; a text column makes both storable and leaves the canonical spelling to
    the service layer in M17.

    ``status`` is ``text`` NOT NULL with **no default**. §8.2 names the column and no vocabulary, so
    any set of values here would be invented, and a default would invent one silently — every row
    would arrive in a state nobody chose. The writer must say what the conversation is.
    """

    __tablename__ = "ai_conversations"

    #: ``gen_random_uuid()``, not UUIDv7: the id appears in API paths, so it is externally visible, and
    #: ADR-0009 keeps time-ordering out of identifiers a party to a case can read.
    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    #: ``CASCADE``: a conversation is case material, not a legal record — the same treatment
    #: ``case_notes`` and ``notifications`` get. The custody and audit ledgers are the tables that
    #: outlive a case (§12), and they say so with ``RESTRICT``.
    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    #: Nullable: a thread exists from the moment it is opened, and a title derived from its first
    #: exchange (AI-08) may not exist yet.
    title: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: ``RESTRICT``, like ``case_notes.author_id``: who opened the thread is attribution, and §12
    #: deactivates users rather than erasing them while cases reference them.
    created_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    #: The *selected* model. ``SET NULL`` rather than ``RESTRICT`` for the reason
    #: ``ai_provider_settings.default_model_id`` gives: retiring a model must not be blocked by a chat
    #: thread, and a thread whose model was retired still has every message's own snapshot.
    model_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("ai_models.id", ondelete="SET NULL"), nullable=True, default=None
    )
    status: Mapped[str] = mapped_column(Text, nullable=False)

    case: Mapped[Case] = relationship(back_populates="conversations")
    created_by_user: Mapped[User] = relationship(foreign_keys=[created_by])
    model: Mapped[AIModel | None] = relationship()
    messages: Mapped[list[AIMessage]] = relationship(
        back_populates="conversation", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # The thread list for a case, newest first — and, per §10, `case_id` leads because ACL
        # scoping applies it to essentially every query.
        Index("ix_ai_conversations_case_created", "case_id", "created_at"),
        Index("ix_ai_conversations_model", "model_id"),
    )


class AIMessage(Base):
    """One turn in a conversation (§8.2). A log row, written once.

    No ``TimestampMixin``, and the omission is deliberate in both directions:

    * ``created_at`` is this row's time, so a second insert-time column would only invite code to read
      the wrong one — the reasoning ``custody_events`` gives for having no ``created_at``.
    * There is no ``updated_at`` because a logged interaction is never edited. AI-08's "regenerate
      with citation view" **appends** a turn rather than rewriting one: an answer an analyst already
      read, quoted in a note or acted on must still be there in the form they saw it. A column that
      never advances is not a harmless extra — it is a claim that the row can change.

    The platform does not enforce that immutability with role privileges, because no ratified document
    puts ``ai_messages`` in the append-only set (§10 names ``audit_logs``, ``custody_events`` and
    ``integrity_checks``). Adding a REVOKE here would be a policy decision dressed as a schema one;
    it belongs to M17, which owns the assistant's write paths and can test them.
    """

    __tablename__ = "ai_messages"

    #: UUIDv7: a transcript is written sequentially and grows without bound, so time-ordered keys keep
    #: the primary index appending at its right-hand edge (§1.1). The id is not a credential and is
    #: not published outside the case, so ADR-0009's disclosure concern does not apply.
    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid7, server_default=text("uuid_generate_v7()")
    )
    conversation_id: Mapped[UUID] = mapped_column(
        ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[ChatRole] = mapped_column(native_enum(ChatRole), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    #: ``[{entity_type, entity_id, snippet, score}]`` — §8.2's shape. Empty means the answer cites
    #: nothing, which for an assistant turn is only lawful alongside ``unsupported=true``.
    citations: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    #: "Not supported by case data" (AI-02). Default false, because the honest state of a new row is
    #: "this claim has not been declared unsupported" — and the CHECK below then forces an assistant
    #: turn to earn its citations or flip this.
    unsupported: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    #: What retrieval actually returned — chunk ids and scores (AI_ARCHITECTURE §6) — so an answer can
    #: be reconstructed and challenged. ``[]`` means nothing was retrieved, which is a fact worth
    #: keeping; NULL would have meant "we did not record it", and the difference between "the case had
    #: nothing" and "we did not look" is exactly what AI-01 turns on.
    retrieval_context: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    #: Snapshot — see the module docstring. Nullable because a turn that failed or was refused may
    #: never have reached a model; the CHECK below requires both for a turn that succeeded.
    model_name: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    model_version: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: Plain ``numeric``, exactly as §8.2 specifies, with no precision invented: a scale chosen here
    #: would silently round a provider's own value, and the number stored should be the number sent.
    temperature: Mapped[Decimal | None] = mapped_column(Numeric(), nullable=True, default=None)
    top_p: Mapped[Decimal | None] = mapped_column(Numeric(), nullable=True, default=None)
    seed: Mapped[int | None] = mapped_column(BigInteger, nullable=True, default=None)
    #: §8.2 makes this NOT NULL: the guardrail revision in force is recorded on every turn, including
    #: a user's, because "which rules was this conversation held to" is a question about the whole
    #: exchange. No default — a default would fabricate a revision for any row that forgot to say.
    guardrail_version: Mapped[str] = mapped_column(Text, nullable=False)
    #: Not in §8.2's column list, and required by AI_ARCHITECTURE (§5's audit fields, §6's invocation
    #: fields, and §12's "``prompt_template_version`` and ``guardrail_version`` on every message and
    #: invocation"). §11.1 makes the prompt template versioned, so an answer reproduced without the
    #: template version is not reproduced. ``text`` to match ``guardrail_version`` beside it: two
    #: version columns in one table should be the same kind of thing, and a label the security team
    #: owns ("v3-guardrails") does not fit an integer. Recorded in ``migrations/README.md``.
    prompt_template_version: Mapped[str] = mapped_column(Text, nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    status: Mapped[AIMessageStatus] = mapped_column(
        # Named explicitly: `_snake("AIMessageStatus")` yields `a_i_message_status`, because the
        # derivation splits every capital and does not know that `AI` is one acronym. The override is
        # what `native_enum(name=…)` exists for (`password_alg` is the other user of it).
        native_enum(AIMessageStatus, name="ai_message_status"),
        nullable=False,
    )
    #: Server-side default, like every other timestamp in the schema: the database clock is the one an
    #: audit trail can defend, and a worker container's clock is not.
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, server_default=func.now()
    )

    conversation: Mapped[AIConversation] = relationship(back_populates="messages")

    __table_args__ = (
        # The transcript read: one conversation's turns, in order. This is the only query the
        # assistant UI makes on every render.
        Index("ix_ai_messages_conversation_created", "conversation_id", "created_at"),
        # AI-02 / §8.2: an assistant turn either cites case data or declares itself unsupported. The
        # model literally cannot persist an uncited claim without saying the case data does not
        # support it — which turns a hallucination from an invisible defect into a recorded one.
        CheckConstraint(
            f"role <> 'assistant' OR {CITATION_COUNT} > 0 OR unsupported = true",
            name="assistant_cites_or_declares_unsupported",
        ),
        # ``jsonb_array_length`` raises `cannot get array length of a non-array` on an object, so
        # without this guard a malformed ``citations`` value would fail the constraint above with an
        # internal error instead of a named CHECK violation. Both reject the row; only one says why.
        CheckConstraint("jsonb_typeof(citations) = 'array'", name="citations_is_a_json_array"),
        # AI-04: an answer that was produced names what produced it. Scoped twice over, and both
        # scopings are load-bearing:
        #   * to `assistant`, because a user's own words and a tool's retrieval result never reached a
        #     model at all — without this clause `succeeded` would be unwritable for them, and the only
        #     statuses left would be "failed" and "refused", which are both lies about a question
        #     somebody simply asked;
        #   * to `succeeded`, because an assistant turn that failed or was refused may have been
        #     stopped before any model ran, and demanding a model name there would mean recording a
        #     model the platform did not use.
        CheckConstraint(
            "role <> 'assistant' OR status <> 'succeeded' "
            "OR (model_name IS NOT NULL AND model_version IS NOT NULL)",
            name="a_succeeded_turn_names_its_model",
        ),
        # top_p is a probability by definition, so [0,1] is not an invented bound. temperature has no
        # universal upper limit across providers, so only its sign is constrained.
        CheckConstraint(
            "top_p IS NULL OR (top_p >= 0 AND top_p <= 1)", name="top_p_is_a_probability"
        ),
        CheckConstraint("temperature IS NULL OR temperature >= 0", name="temperature_not_negative"),
        CheckConstraint(
            "prompt_tokens IS NULL OR prompt_tokens >= 0", name="prompt_tokens_not_negative"
        ),
        CheckConstraint(
            "completion_tokens IS NULL OR completion_tokens >= 0",
            name="completion_tokens_not_negative",
        ),
        CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="latency_not_negative"),
        CheckConstraint("seed IS NULL OR seed >= 0", name="seed_not_negative"),
    )
