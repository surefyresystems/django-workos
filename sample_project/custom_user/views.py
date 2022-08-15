from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.contrib.auth import get_user_model


# Create your views here.
from workos_login.models import LoginRule


@login_required
def home(request):
    ctx = {
        "rules": LoginRule.objects.all(),
        "users": get_user_model().objects.all()
    }
    return render(request, "home.html", ctx)
