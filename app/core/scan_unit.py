"""
ScanUnit — the input model for the dynamic analyzer.
Replaces the simple URL string with a rich context object
that tells plugins exactly what to test and how.
"""
from pydantic import BaseModel
from typing import Optional, List, Dict
from enum import Enum

class ScanUnitType(str, Enum):
    URL   = "url"    # scan a full page
    FORM  = "form"   # scan a specific form
    PARAM = "param"  # scan a specific parameter

class ParamLocation(str, Enum):
    QUERY  = "query"
    FORM   = "form"
    HEADER = "header"
    COOKIE = "cookie"
    PATH   = "path"

class FormInput(BaseModel):
    name:          str
    input_type:    str                    # text, hidden, password, etc.
    sample:        Optional[str] = None
    sensitive:     bool = False           # e.g. password fields

class ScanUnit(BaseModel):
    type:          ScanUnitType
    url:           str                    # always required
    method:        str = "GET"
    params:        Dict[str, str] = {}   # query/form params
    headers:       Dict[str, str] = {}
    snapshot_id:   Optional[str] = None  # from moku tracker
    auth_required: bool = False

    # for form scans
    form_id:       Optional[str] = None
    form_action:   Optional[str] = None
    inputs:        List[FormInput] = []

    # for param scans
    parameter_name: Optional[str] = None
    location:       Optional[ParamLocation] = None
    sample_value:   Optional[str] = None

    # scan options
    plugins:               List[str] = []   # empty = run all plugins
    allow_aggressive:      bool = False      # opt-in for aggressive tests
    headless_preference:   str = "auto"      # auto | on | off