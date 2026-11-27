from django.urls import include, path

from .links import urls as link_urls
from .views import IntegrationView, NoteView

urlpatterns = [
    path("integrations/<int:integration_id>/", IntegrationView.as_view()),
    path("notes/<int:note_id>/", NoteView.as_view()),
    path("links/", include(link_urls)),
]
