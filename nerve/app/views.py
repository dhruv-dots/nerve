from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import *
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
# Create your views here.

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class signup_view(APIView):
    def post(self,request):
        serializer=UserSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)
        user=serializer.save()
        token = get_tokens_for_user(user)
        return Response({'token':token,'message':'registration successful'},status=status.HTTP_201_CREATED)

class login_view(APIView):
   
    def post(self,request):
        serializer=UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            username=serializer.data.get('username')
            password=serializer.data.get('password')
            user=authenticate(username=username,password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token':token,'msg':'Login success'},status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non_field_errors':['username or password is not valid']}},status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializers.errors,status=status.HTTP_400_BAD_REQUEST)    
    
class details_view(APIView):
    permission_classes=[IsAuthenticated]
    def get(self,request):
        serializer=UserDetailsSerializer(request.user)
        return Response(serializer.data,status=status.HTTP_200_OK)    

class SendPasswordReset_view(APIView):
    def post(self,request):
        serializer=SendResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message':'password rest link send'},status=status.HTTP_200_OK)
    
class PasswordReset_view(APIView):
    def post(self, request,uid,token):
        serializer=UserResetPasswordSerializer(data=request.data,context={'uid':uid,'token':token})
        serializer.is_valid(raise_exception=True)
        return Response({'message':'password reset successful'},status=status.HTTP_200_OK)
    


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'message':"logout successfuly"},status=status.HTTP_204_NO_CONTENT)