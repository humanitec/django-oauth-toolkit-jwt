from django.urls import re_path
from oauth2_provider import views

from .views import TokenView, JWTAuthorizationView

app_name = "oauth2_provider_jwt"

urlpatterns = [
    re_path(r"^authorize/$", JWTAuthorizationView.as_view(), name="authorize"),
    re_path(r"^token/$", TokenView.as_view(), name="token"),
    re_path(r"^revoke_token/$", views.RevokeTokenView.as_view(),
            name="revoke-token"),
    re_path(r"^introspect/$", views.IntrospectTokenView.as_view(),
            name="introspect"),
]
