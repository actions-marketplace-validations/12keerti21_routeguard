from site.app.models import Asset, Bookmark


def bookmark_read(request, bookmark_id):
    bookmark = Bookmark.objects.get(pk=bookmark_id)
    if bookmark.owner != request.user:
        raise Http404("Bookmark does not exist")
    return bookmark


def asset_read(request, asset_id):
    asset = Asset.objects.get(pk=asset_id)
    bookmark_read(request, asset.bookmark_id)
    return asset
