from django.urls import path

from site.app.views import bulk_action

urlpatterns = [
    path("bulk/<str:model_name>/<int:pk>/", bulk_action),
]

urlpatterns = decorate_urlpatterns(urlpatterns, require_admin_access)
