"""API router aggregation."""

from fastapi import APIRouter

from app.api.routes.assets import router as assets_router
from app.api.routes.businesses import router as businesses_router
from app.api.routes.scans import router as scans_router

api_router = APIRouter()
api_router.include_router(businesses_router)
api_router.include_router(assets_router)
api_router.include_router(scans_router)
