from django.urls import path

from site.app.views import AssetView, AssetReadView, ProjectViewSet, UnsplashView

urlpatterns = [
    path("projects/<uuid:pk>/", ProjectViewSet.as_view({"delete": "destroy", "patch": "partial_update"})),
    path("boards/<str:anchor>/assets/<int:pk>/", AssetView.as_view()),
    path("assets/<int:asset_id>/", AssetReadView.as_view()),
    path("unsplash/", UnsplashView.as_view()),
]
