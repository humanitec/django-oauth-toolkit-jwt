import json

from django.conf.urls import include, url
from django.contrib import admin
from django.http import HttpResponse
from rest_framework import permissions
from rest_framework.views import APIView
from oauth2_provider.contrib.rest_framework import TokenHasScope

admin.autodiscover()


class MockView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, _request):
        return HttpResponse('mockview-get')

    def post(self, request):
        response = json.dumps(dict(request.session))
        return HttpResponse(response)


class MockForAuthView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, _request):
        return HttpResponse('mockforauthview-get')

    def post(self, request):
        response = json.dumps({"username": request.user.username})
        return HttpResponse(response)


class MockForAuthScopeView(APIView):
    permission_classes = (TokenHasScope,)
    required_scopes = ['write']

    def get(self, _request):
        return HttpResponse('mockforauthscopeview-get')

    def post(self, request):
        response = json.dumps({"username": request.user.username})
        return HttpResponse(response)


urlpatterns = [
    url(r"^o/", include("oauth2_provider_jwt.urls",
                        namespace="oauth2_provider_jwt")),
    url(r'^jwt/$', MockView.as_view()),
    url(r'^jwt_auth/$', MockForAuthView.as_view()),
    url(r'^jwt_auth_scope/$', MockForAuthScopeView.as_view()),
]


urlpatterns += [url(r"^admin/", admin.site.urls)]
