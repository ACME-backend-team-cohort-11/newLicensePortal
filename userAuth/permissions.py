from rest_framework.permissions import BasePermission

class IsRegularUser(BasePermission):
    """Allow access only to admin users"""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and not request.user.is_staff)