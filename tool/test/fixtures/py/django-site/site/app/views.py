import requests
from rest_framework import viewsets
from rest_framework.views import APIView

from site.app import access
from site.app.models import Asset, Board, Project, ProjectMember


class ProjectViewSet(viewsets.ViewSet):
    # a membership check with exists() before the delete
    def destroy(self, request, pk):
        if ProjectMember.objects.filter(member=request.user, project_id=pk, role="admin").exists():
            Project.objects.get(pk=pk).delete()

    @allow_permission(["ADMIN"])
    def partial_update(self, request, pk):
        Project.objects.filter(pk=pk).update(name=request.data["name"])


class AssetView(APIView):
    # the published board is public; the asset must be the caller's
    def patch(self, request, anchor, pk):
        board = Board.objects.filter(anchor=anchor).first()
        asset = Asset.objects.filter(id=pk, board=board, created_by=request.user).first()
        asset.save()

    def delete(self, request, anchor, pk):
        board = Board.objects.filter(anchor=anchor).first()
        Asset.objects.filter(id=pk, board=board).first().delete()


class AssetReadView(APIView):
    def get(self, request, asset_id):
        return access.asset_read(request, asset_id)


class UnsplashView(APIView):
    def get(self, request):
        query = request.GET.get("query")
        url = f"https://api.unsplash.com/search/?query={query}" if query else "https://api.unsplash.com/photos/"
        return requests.get(url)


def bulk_action(request, model_name, pk):
    Asset.objects.get(pk=pk).delete()
