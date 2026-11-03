from app.api.v1.admin import router as admin_router
from app.api.v1.assets import router as assets_router
from app.api.v1.autonomy import router as autonomy_router
from app.api.v1.campaign_runs import router as campaign_runs_router
from app.api.v1.findings import router as findings_router
from app.api.v1.governance import router as governance_router
from app.api.v1.objectives import catalog_router
from app.api.v1.objectives import router as objectives_router

__all__ = [
    "admin_router",
    "assets_router",
    "autonomy_router",
    "campaign_runs_router",
    "catalog_router",
    "findings_router",
    "governance_router",
    "objectives_router",
]
