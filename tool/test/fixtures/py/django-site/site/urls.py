from django.urls import include, path

urlpatterns = [
    path("api/", include("site.app.urls")),
    path("admin/", include("site.admin_urls")),
]

urlpatterns = [path("__debug__/", include("debug_toolbar.urls"))] + urlpatterns
