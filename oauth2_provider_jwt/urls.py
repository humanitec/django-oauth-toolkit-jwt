from django.urls import path
from oauth2_provider import views

from .views import TokenView, JWTAuthorizationView

app_name = "oauth2_provider_jwt"

urlpatterns = [
    path("authorize/", JWTAuthorizationView.as_view(), name="authorize"),
    path("token/", TokenView.as_view(), name="token"),
    path("revoke_token/", views.RevokeTokenView.as_view(),
        name="revoke-token"),
    path("introspect/", views.IntrospectTokenView.as_view(),
        name="introspect"),
]
