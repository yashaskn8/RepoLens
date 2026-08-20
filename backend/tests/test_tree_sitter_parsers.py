"""Unit tests for Tree-sitter parsing of Python, JavaScript, TypeScript, and TSX files."""

import pytest
from app.ingestion.parser import parse_file
from app.ingestion.schemas import SymbolKind


def test_parse_python_functions_classes_imports():
    """Verify that Python functions, classes, and import statements are extracted accurately."""
    source_code = b"""
import os
import sys
from typing import List, Optional
from pydantic import BaseModel

class UserProfile(BaseModel):
    id: int
    username: str

    def get_display_name(self) -> str:
        return self.username.title()

async def fetch_remote_user(user_id: int) -> Optional[UserProfile]:
    return None

def compute_hash(data: str) -> str:
    return "hash123"
"""
    symbols = parse_file("src/models/user.py", "python", source_code)

    names_by_kind = {k: [] for k in SymbolKind}
    for s in symbols:
        names_by_kind[s.kind].append(s.name)

    assert "import os" in names_by_kind[SymbolKind.IMPORT]
    assert "from pydantic import BaseModel" in names_by_kind[SymbolKind.IMPORT]
    assert "UserProfile" in names_by_kind[SymbolKind.CLASS]
    assert "fetch_remote_user" in names_by_kind[SymbolKind.FUNCTION]
    assert "compute_hash" in names_by_kind[SymbolKind.FUNCTION]


def test_parse_python_fastapi_routes():
    """Verify that FastAPI route decorators (@app.get, @router.post) are extracted as FASTAPI_ROUTE symbols."""
    source_code = b"""
from fastapi import APIRouter, Depends, HTTPException

router = APIRouter(prefix="/users", tags=["Users"])

@router.get("/{user_id}", response_model=UserResponse)
def get_user_by_id(user_id: int):
    return {"id": user_id}

@router.post("/login", status_code=200)
async def authenticate_user(payload: LoginRequest):
    return {"token": "jwt-token"}

@app.delete("/admin/purge")
def purge_records():
    pass
"""
    symbols = parse_file("app/api/users.py", "python", source_code)

    routes = [s for s in symbols if s.kind == SymbolKind.FASTAPI_ROUTE]
    assert len(routes) == 3

    route_map = {r.details.get("http_method"): r.details for r in routes}
    assert "GET" in route_map
    assert route_map["GET"]["path"] == "/{user_id}"
    assert route_map["GET"]["handler"] == "get_user_by_id"

    assert "POST" in route_map
    assert route_map["POST"]["path"] == "/login"
    assert route_map["POST"]["handler"] == "authenticate_user"

    assert "DELETE" in route_map
    assert route_map["DELETE"]["path"] == "/admin/purge"


def test_parse_javascript_typescript_express_and_functions():
    """Verify that TypeScript/JavaScript functions, classes, and Express routes are extracted."""
    source_code = b"""
import express, { Request, Response } from 'express';
const router = express.Router();

export class AuthService {
    public validateToken(token: string): boolean {
        return token.length > 0;
    }
}

router.get('/profile', async (req: Request, res: Response) => {
    res.json({ status: 'ok' });
});

router.post('/register', (req: Request, res: Response) => {
    res.status(201).json({ created: true });
});

export const calculateTax = (amount: number): number => {
    return amount * 0.15;
};

function formatCurrency(val: number): string {
    return '$' + val.toFixed(2);
}
"""
    symbols = parse_file("server/routes/auth.ts", "typescript", source_code)

    kinds = {s.kind for s in symbols}
    assert SymbolKind.CLASS in kinds
    assert SymbolKind.EXPRESS_ROUTE in kinds
    assert SymbolKind.FUNCTION in kinds
    assert SymbolKind.IMPORT in kinds

    routes = [s for s in symbols if s.kind == SymbolKind.EXPRESS_ROUTE]
    assert len(routes) == 2
    route_paths = [r.details.get("path") for r in routes]
    assert "/profile" in route_paths
    assert "/register" in route_paths

    func_names = [s.name for s in symbols if s.kind == SymbolKind.FUNCTION]
    assert "calculateTax" in func_names
    assert "formatCurrency" in func_names


def test_parse_tsx_fetch_and_axios_calls():
    """Verify that TSX React components with fetch and axios calls are extracted."""
    source_code = b"""
import React, { useEffect, useState } from 'react';
import axios from 'axios';

export const UserDashboard: React.FC = () => {
    const [data, setData] = useState(null);

    useEffect(() => {
        fetch('/api/v1/health')
            .then(res => res.json())
            .then(d => setData(d));

        axios.get('https://api.external.com/v1/metrics')
            .then(resp => console.log(resp.data));
    }, []);

    return (
        <div className="container">
            <h1>Dashboard</h1>
        </div>
    );
};
"""
    symbols = parse_file("src/components/UserDashboard.tsx", "tsx", source_code)

    fetch_calls = [s for s in symbols if s.kind == SymbolKind.FETCH_CALL]
    axios_calls = [s for s in symbols if s.kind == SymbolKind.AXIOS_CALL]

    assert len(fetch_calls) >= 1
    assert "/api/v1/health" in fetch_calls[0].details.get("target", "")

    assert len(axios_calls) >= 1
    assert "metrics" in axios_calls[0].details.get("target", "")
