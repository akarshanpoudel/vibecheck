from django.http import JsonResponse


def health(request):
    """
    GET /health/ — used by load balancers and uptime monitors.
    Returns 200 as long as the app process is alive.
    Does not check the database — that would turn a DB blip into
    a full service outage from the load balancer's perspective.
    """
    return JsonResponse({"ok": True})