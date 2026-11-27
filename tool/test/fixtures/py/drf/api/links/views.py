from rest_framework.views import APIView

from api.models import Link


class LinkView(APIView):
    def delete(self, request, link_id):
        Link.objects.get(pk=link_id).delete()
