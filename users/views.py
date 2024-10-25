import bcrypt
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

# user register
class RegisterView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if User.objects.filter(username=username).exists():
            return Response({'message': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # use bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # create user
        user = User.objects.create(username=username, password=hashed_password)

        return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)


# user login
class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # verify pwd
        if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)


# reset pwd
class PasswordResetView(APIView):
    def post(self, request, id):
        new_password = request.data.get('new_password')

        try:
            # by id
            user = User.objects.get(id=id)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # use bcrypt 
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # update
        user.password = hashed_password
        user.save()

        return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
