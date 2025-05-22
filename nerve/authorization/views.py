from django.shortcuts import render
from django.shortcuts import render,redirect
from .models import *
from .forms import *
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required
# Create your views here.

@login_required
def homeView(request):
    return render(request,'authorization/home.html')

def signupView(request):
    if request.method=='POST':
        form=SignUpForm(request.POST)

        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form=SignUpForm()    
    return render(request,'authorization/signup.html',{'form':form})

def logoutView(request):
    return render(request,'authorization/logout-user.html')