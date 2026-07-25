from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path


def robots_txt(request):
    lines = [
        "User-agent: *",
        "Disallow: /scan/",    # keep result pages (which contain redacted keys) out of indexes
        "Disallow: /admin/",
        "",
    ]
    return HttpResponse("\n".join(lines), content_type="text/plain")


urlpatterns = [
    path("robots.txt", robots_txt),
    path("admin/",     admin.site.urls),
    path("",           include("scanner.urls")),
]