from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import *


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'content', 'timestamp')
    list_filter = ('sender', 'receiver', 'timestamp')
    search_fields = ('sender__username', 'receiver__username', 'content')



class TodoUserProfileInline(admin.StackedInline):
      model= TodoUserProfile


class TodoUserAdmin(UserAdmin):
    inlines = (TodoUserProfileInline, )


admin.site.unregister(User)
admin.site.register(User, TodoUserAdmin)