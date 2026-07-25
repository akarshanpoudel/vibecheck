from django.urls import path
from . import views

app_name = "scanner"

urlpatterns = [
    path("",                          views.index,         name="index"),
    path("scan/<slug:slug>/",         views.result,        name="result"),
    path("scan/<slug:slug>/status/",  views.scan_status,   name="status"),
    path("history/clear/",            views.clear_history, name="clear_history"),
]