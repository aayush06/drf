import json
import base64
import os

from django.shortcuts import redirect, render_to_response
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.views import generic
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import get_user_model
from django.views.generic import TemplateView

from rest_framework.views import APIView
from rest_framework_jwt.settings import api_settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.renderers import TemplateHTMLRenderer

from .serializers import TokenSerializer, UserSerializer, SnippetSerializer, LoginSerializer
from .models import Snippet

# Get the JWT settings.
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
User = get_user_model()


ERROR_405 = "405 Method Not Aljwt_encode_handler"

def decrypt_snippet(key, snippet_text):
    dec = []
    enc = base64.urlsafe_b64decode(snippet_text).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
    

class RegisterView(APIView):
    """
    POST snippet/api/register/
    """
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'register.html'
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        serializer = UserSerializer()
        return Response({'serializer': serializer})

    def post(self, request, format='json'):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                data = {
                    'id': user.user_id,
                    'token': jwt_encode_handler(jwt_payload_handler(user)),
                    'email': serializer.data.get('email', ''),
                    'success': True
                }
                if request.accepted_renderer.format == "html":
                    return redirect("login")
                return Response(data, status=status.HTTP_201_CREATED)
            return HttpResponse("User not registered successfully")
        return HttpResponse(str(serializer.user_check.message))
        

class LoginView(APIView):
    """
    POST snippet/api/login/
    """
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'login.html'
    permission_classes = (permissions.AllowAny,)
    def get(self, request):
        serializer = LoginSerializer()
        return Response({'serializer': serializer})

    def post(self, request, *args, **kwargs):
        email = request.data.get("email", "")
        password = request.data.get("password", "")
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            data = {
                    'id': user.user_id,
                    'token': jwt_encode_handler(jwt_payload_handler(user)),
                    'email': email,
                    'success': True
                }
            serializer = TokenSerializer(data=data)
            serializer.is_valid()
            if request.accepted_renderer.format == "html":
                return redirect("add_snippet")
            else:
                return Response(data, status=status.HTTP_201_CREATED)
        serializer = LoginSerializer()
        return Response({"serializer": serializer})


class AddSnippet(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'add_snippet.html'
    authentication_classes = (SessionAuthentication, )
    permission_classes = (permissions.IsAuthenticated,)
    def get(self, request):
        resp_dict = {"success": True, "data": {},
                     "summary": "Snippet found successfully"}
        try:
            snippet_id = request.GET.get('snippet_id', None)
            key = request.GET.get('key', None)
            if snippet_id:
                snippet = Snippet.objects.get(snippet_id=snippet_id)
                if key:
                    if key == snippet.key:
                        text_snippet = decrypt_snippet(key, snippet.text_snippet)
                    else:
                        raise Exception("key doesn't match")
                else:
                    text_snippet = snippet.text_snippet
                return HttpResponse(text_snippet)  
            else:
                serializer = SnippetSerializer()
                return Response({'serializer': serializer})
        except Exception as e:
            return HttpResponse(str(e))
        return JsonResponse(resp_dict)
            
    authentication_classes = (SessionAuthentication, )
    permission_classes = (permissions.IsAuthenticated,)
    def post(self, request):
        resp_dict = {"success": True, "data": [],
                     "summary": "Snippet added successfully"}
        try:
            user = request.user
            domain = request.META.get('HTTP_HOST', '')
            text_snippet = str(request.data.get("text_snippet", ""))
            key = request.data.get("key", None)
            if not text_snippet:
                raise Exception("snippet text is required.")
            if key:
                serializer = SnippetSerializer(data={'user_id':user, 'text_snippet':text_snippet, 'key':key})
            else:
                serializer = SnippetSerializer(data={'user_id':user, 'text_snippet':text_snippet})
            if serializer.is_valid():
                snippet = serializer.save()
                if key:
                    shareable_url = '{}/snippet/get_snippet?snippet_id={}&key={}'.format(domain, snippet.snippet_id, key)
                else:
                    shareable_url = '{}/snippet/get_snippet?snippet_id={}'.format(domain, snippet.snippet_id)
                if snippet:
                    data = {
                        'snippet_id': snippet.snippet_id,
                        'shareable_url':shareable_url,
                        'success': True
                    }
                    if request.accepted_renderer.format == "html":
                        request.session['shareable_url'] = shareable_url
                        return redirect("share") # Need to change this.
                    return Response(data, status=status.HTTP_201_CREATED)
            return Response({"success": False}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            resp_dict["success"] = False
            resp_dict["summary"] = str(e)
            return JsonResponse(resp_dict)


class ShareSnippet(APIView):

    authentication_classes = (SessionAuthentication, )
    permission_classes = (permissions.AllowAny,)
    def get(self, request):
        shareable_url = request.session.get("shareable_url")
        return HttpResponse(shareable_url)