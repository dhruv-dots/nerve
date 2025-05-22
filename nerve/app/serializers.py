from .models import *
from rest_framework import serializers
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

class UserSerializers(serializers.ModelSerializer):
    conf_password=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['email','username','password','conf_password']
        extra_kwargs={
            'password':{'write_only':True}
        }

    def validate(self, attrs):
        password=attrs.get('password')
        conf_password=attrs.get('conf_password')

        if password!=conf_password:
            raise serializers.ValidationError("password and confirm password doesn't match")
        return attrs

    def create(self,validate_data):
        return User.objects.create_user(**validate_data)

class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=300)
    class Meta:
        model=User
        fields=['username','password']    

class UserDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','username','email']


class UserChangePasswordSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  conf_password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'conf_password']

  def validate(self, attrs):
    password = attrs.get('password')
    conf_password = attrs.get('conf_password')
    user = self.context.get('user')
    if password != conf_password:
      raise serializers.ValidationError("Password and Confirm Password doesn't match")
    user.set_password(password)
    user.save()
    return attrs


class SendResetPasswordSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=300)   
    class Meta:
        fields=['email']

    def validate(self, attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            token=PasswordResetTokenGenerator().make_token(user)
            link='http://127.0.0.1:8000/reset/'+uid+'/'+token
            print('password reset link:',link)
            return attrs
        else:
            raise serializers.ValidationError("you are not a registered user")

class UserResetPasswordSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)             
    conf_password=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True) 

    class Meta:
        fields=['password','conf_password']

    def validate(self, attrs):
        try:
            password=attrs.get('password')                
            conf_password=attrs.get('conf_password') 
            uid=self.context.get('uid')
            token=self.context.get('token')
            if password!=conf_password:
                raise serializers.ValidationError("password and confirm password does not match")
            id=smart_str(urlsafe_base64_decode(uid))
            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise serializers.ValidationError('Token is not Valid or Expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user,token)
            raise serializers.ValidationError("token is not valid or token is expired")


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')              