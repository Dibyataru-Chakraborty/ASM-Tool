"""Tenant-aware asset/domain target management."""
from typing import Optional, List, Dict, Any
import json, logging
from sqlalchemy.orm import Session
from app.models import Asset, Domain
from app.repositories.domain_repo import DomainRepository
from app.exceptions import NotFoundError, ConflictError, ValidationError
logger=logging.getLogger(__name__)

class AssetService:
    def __init__(self,db:Session): self.db=db; self.domain_repo=DomainRepository(db)

    def create_asset(self, organization_id:str, user_id:str, name:str, target:str, description:Optional[str]=None, asset_type:str="domain", tags:Optional[List[str]]=None)->Asset:
        if not name or not name.strip(): raise ValidationError("Asset name cannot be empty")
        domain_name=self._domain_from_target(target)
        if asset_type in {"domain","subdomain","url","web_application","organization"} and not domain_name:
            raise ValidationError("Domain and URL assets require a valid hostname")
        if self.db.query(Asset).filter(Asset.organization_id==organization_id,Asset.name==name.strip(),Asset.status!="archived").first():
            raise ConflictError(f"Asset '{name}' already exists in this organization")
        asset=Asset(organization_id=organization_id,user_id=user_id,name=name.strip(),target=target.strip(),description=description,
                    asset_type=asset_type,tags=json.dumps(tags or []),status="active",risk_score=0)
        self.db.add(asset); self.db.flush()
        if domain_name:
            domain=Domain(organization_id=organization_id,asset_id=asset.id,domain=domain_name,is_active=True,is_vulnerable=False,scan_status="not_scanned")
            self.db.add(domain); self.db.flush()
            from app.services.attack_surface_service import AttackSurfaceService
            AttackSurfaceService(self.db).ensure_primary_seed(organization_id,domain)
        self.db.commit(); self.db.refresh(asset); return asset

    def get_asset(self,asset_id:str,organization_id:str)->Asset:
        row=self.db.query(Asset).filter(Asset.id==asset_id,Asset.organization_id==organization_id).first()
        if not row: raise NotFoundError("Asset")
        return row
    def list_assets(self,organization_id:str,skip:int=0,limit:int=10):
        q=self.db.query(Asset).filter(Asset.organization_id==organization_id); return q.offset(skip).limit(limit).all(),q.count()
    def list_active_assets(self,organization_id:str,skip:int=0,limit:int=10):
        q=self.db.query(Asset).filter(Asset.organization_id==organization_id,Asset.status!="archived"); return q.offset(skip).limit(limit).all(),q.count()
    def update_asset(self,asset_id:str,organization_id:str,**kwargs)->Asset:
        asset=self.get_asset(asset_id,organization_id)
        for key in ("name","target","description","status","asset_type"):
            val=kwargs.get(key)
            if val is not None: setattr(asset,key,val.strip() if isinstance(val,str) else val)
        if kwargs.get("tags") is not None: asset.tags=json.dumps(kwargs["tags"])
        self.db.commit(); self.db.refresh(asset); return asset
    def delete_asset(self,asset_id:str,organization_id:str)->bool:
        self.db.delete(self.get_asset(asset_id,organization_id)); self.db.commit(); return True
    def archive_asset(self,asset_id:str,organization_id:str)->Asset:
        a=self.get_asset(asset_id,organization_id); a.status="archived"; self.db.commit(); self.db.refresh(a); return a
    def get_asset_stats(self,asset_id:str,organization_id:str)->Dict[str,Any]:
        a=self.get_asset(asset_id,organization_id); ds=self.db.query(Domain).filter(Domain.asset_id==a.id).all()
        return {"asset_id":a.id,"name":a.name,"total_domains":len(ds),"vulnerable_domains":sum(d.is_vulnerable for d in ds),
                "total_subdomains":sum(len(d.subdomains) for d in ds),"risk_score":a.risk_score,"status":a.status,"last_scanned":a.updated_at}
    def calculate_risk_score(self,asset_id:str)->int:
        a=self.db.query(Asset).filter(Asset.id==asset_id).first(); return int(a.risk_score or 0) if a else 0
    @staticmethod
    def _domain_from_target(target:str)->Optional[str]:
        from urllib.parse import urlparse
        value=(target or "").strip().lower(); parsed=urlparse(value if "://" in value else f"//{value}"); host=(parsed.hostname or "").rstrip(".")
        labels=host.split(".") if host else []
        if len(labels)<2 or not labels[-1].isalpha() or len(labels[-1])<2 or any(not x or len(x)>63 for x in labels): return None
        return host
