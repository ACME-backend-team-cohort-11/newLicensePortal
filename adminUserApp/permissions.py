from rest_framework.permissions import BasePermission

class IsAdminUserCustom(BasePermission):
    """Allow access only to admin users"""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_staff)