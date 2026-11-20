"""M13 detector/tracker contracts without an AGPL dependency."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class Detection:
    frame_index:int
    cls:str
    confidence:float
    bbox:tuple[float,float,float,float]

class GreedyTracker:
    """Small deterministic association fallback; production ByteTrack can replace this adapter."""
    def __init__(self,iou_threshold:float=.3)->None:
        self.iou_threshold=iou_threshold
        self.next_id=1
        self.tracks:dict[int,Detection]={}
    @staticmethod
    def iou(a:tuple[float,float,float,float],b:tuple[float,float,float,float])->float:
        ax1,ay1,ax2,ay2=a; bx1,by1,bx2,by2=b
        ix=max(0,min(ax2,bx2)-max(ax1,bx1)); iy=max(0,min(ay2,by2)-max(ay1,by1))
        inter=ix*iy; area=(ax2-ax1)*(ay2-ay1)+(bx2-bx1)*(by2-by1)-inter
        return inter/area if area else 0.0
    def update(self,detections:list[Detection])->list[tuple[int,Detection]]:
        result=[]
        for det in detections:
            best=max(((tid,self.iou(old.bbox,det)) for tid,old in self.tracks.items()),key=lambda x:x[1],default=(0,0.0))
            tid=best[0] if best[1]>=self.iou_threshold else self.next_id
            if tid==self.next_id:self.next_id+=1
            self.tracks[tid]=det; result.append((tid,det))
        return result
