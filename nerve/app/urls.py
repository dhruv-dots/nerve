from django.urls import path
from .views import *




urlpatterns = [   
    path('signup/',signup_view.as_view(),name='signup'),
    path('login/',login_view.as_view(),name='login'),
    path('details/',details_view.as_view(),name='details'),
    path('send-reset/',SendPasswordReset_view.as_view(),name='send-reset'),
    path('reset/<uid>/<token>',PasswordReset_view.as_view(),name='reset'),
    path('logout/', LogoutView.as_view(), name='logout'),

]