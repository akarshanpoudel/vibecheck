from django.urls import path
from . import views

app_name = "scanner"

urlpatterns = [
    path("",                          views.index,       name="index"),
    path("scan/<int:scan_id>/",       views.result,      name="result"),
    path("scan/<int:scan_id>/status/",views.scan_status, name="status"),
]