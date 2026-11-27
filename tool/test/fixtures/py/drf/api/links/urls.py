from django.urls import path

from .views import LinkView

urlpatterns = [
    path("<int:link_id>/", LinkView.as_view()),
]
