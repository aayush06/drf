from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from django.contrib.auth import get_user_model

from rest_framework.validators import UniqueValidator
from .models import Snippet

User = get_user_model()


class TokenSerializer(serializers.Serializer):
    """
    This serializer serializes the token data
    """
    token = serializers.CharField(max_length=255)
    email = serializers.CharField()
    success = serializers.BooleanField(default=False)
    id = serializers.IntegerField()

class UserSerializer(serializers.ModelSerializer):
    user_check = UniqueValidator(queryset=User.objects.all(), message='Email already exists')
    email = serializers.EmailField(
            required=True,
            validators=[user_check],
            style={'input_type':'email','placeholder': 'Email', 'autofocus': True}
            )
    username = serializers.CharField(style={'input_type':'text','placeholder': 'Username', 'autofocus': True})
    password = serializers.CharField(min_length=8, style={'input_type':'password','placeholder': 'password', 'autofocus': True})

    def create(self, validated_data):
        user = User.objects.create_user(validated_data['username'], validated_data['email'],
            validated_data['password'])
        return user

    class Meta:
        model = User
        fields = ('username', 'email', 'password')

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
            required=True,
            style={'input_type':'email','placeholder': 'Email', 'autofocus': True}
            )
    password = serializers.CharField(min_length=8, style={'input_type':'password','placeholder': 'password', 'autofocus': True})

    class Meta:
        model = User
        fields = ('email', 'password')

class SnippetSerializer(serializers.ModelSerializer):
    # user_id = serializers.RelatedField(source='user', queryset=User.objects.all())
    user_id = serializers.ReadOnlyField(source='User.user_id')
    text_snippet = serializers.CharField(style={'input_type':'text','placeholder': 'Snippet', 'autofocus': True})
    key = serializers.CharField(required=False, style={'input_type':'key','placeholder': 'Key', 'autofocus': True})

    def to_internal_value(self, value):
        return value

    def create(self, validated_data):
        snippet = Snippet.objects.create(**validated_data)
        return snippet

    class Meta:
        model = Snippet
        fields = ('user_id', 'text_snippet', 'key')