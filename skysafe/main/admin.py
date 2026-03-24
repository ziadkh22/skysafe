from django.contrib import admin
from .models import UserProfile


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display  = ('username', 'name', 'email', 'job_title', 'nationality', 'created_at')
    search_fields = ('username', 'name', 'email', 'job_title')
    list_filter   = ('job_title', 'nationality', 'gender')
