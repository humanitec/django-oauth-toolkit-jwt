# import ast

from oauth2_provider import views


class TokenView(views.TokenView):
    def post(self, request, *args, **kwargs):
        response = super(TokenView, self).post(request, *args, **kwargs)
        # if response.status_code == 200 and access_token in content:
        #     content = ast.literal_eval(response.content.decode("utf-8"))
        #     content['access_token_jwt'] = ...
        #     content = bytes(json.dumps(content), 'utf-8')
        #     response.content = content
        return response
