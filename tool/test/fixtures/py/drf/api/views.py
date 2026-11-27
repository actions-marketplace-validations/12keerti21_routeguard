from rest_framework.views import APIView

from api.models import Integration, Note
from core.actions import DeleteIntegrationAction


class IntegrationHandler:
    def get_integration(self, integration_id):
        return Integration.objects.get(id=integration_id)


class IntegrationView(APIView):
    # the record and the caller go on together to an action that checks them
    def delete(self, request, integration_id):
        integration = IntegrationHandler().get_integration(integration_id)
        DeleteIntegrationAction.do(request.user, integration)


class NoteView(APIView):
    def delete(self, request, note_id):
        note = Note.objects.get(pk=note_id)
        note.delete()
