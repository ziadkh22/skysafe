from django.urls import path
from . import views

urlpatterns = [
    path('',             views.landing_view,     name='landing'),
    path('login/',       views.login_view,       name='login'),
    path('signup/',      views.signup_view,      name='signup'),
    path('dashboard/',   views.dashboard_view,   name='dashboard'),
    path('admin-login/', views.admin_login_view,  name='admin_login'),
    path('admin-logout/',views.admin_logout_view, name='admin_logout'),
    path('employee/',    views.employee_view,    name='employee'),
    path('logout/',      views.logout_view,      name='logout'),

    # Admin employee management
    path('manage/employees/',
         views.admin_employees_view,     name='admin_employees'),
    path('manage/employees/<int:pk>/edit/',
         views.admin_edit_employee_view, name='admin_edit_employee'),
    path('manage/employees/<int:pk>/warn/',
         views.admin_send_warning_view,  name='admin_send_warning'),

    # Admin control panel
    path('manage/control/', views.admin_control_view, name='admin_control'),

    # Notifications polling
    path('manage/api/notifications/', views.api_notifications, name='api_notifications'),

    # CyberThreat
    path('manage/api/cyber/add/',            views.api_cyber_add,    name='api_cyber_add'),
    path('manage/api/cyber/<int:pk>/edit/',  views.api_cyber_edit,   name='api_cyber_edit'),
    path('manage/api/cyber/<int:pk>/delete/',views.api_cyber_delete, name='api_cyber_delete'),

    # IoTDevice
    path('manage/api/iot/add/',            views.api_iot_add,    name='api_iot_add'),
    path('manage/api/iot/<int:pk>/edit/',  views.api_iot_edit,   name='api_iot_edit'),
    path('manage/api/iot/<int:pk>/delete/',views.api_iot_delete, name='api_iot_delete'),

    # CameraAccessLog
    path('manage/api/camera/add/',            views.api_camera_add,    name='api_camera_add'),
    path('manage/api/camera/<int:pk>/edit/',  views.api_camera_edit,   name='api_camera_edit'),
    path('manage/api/camera/<int:pk>/delete/',views.api_camera_delete, name='api_camera_delete'),

    # FireAlert
    path('manage/api/fire/add/',            views.api_fire_add,    name='api_fire_add'),
    path('manage/api/fire/<int:pk>/edit/',  views.api_fire_edit,   name='api_fire_edit'),
    path('manage/api/fire/<int:pk>/delete/',views.api_fire_delete, name='api_fire_delete'),

    # CrowdedGate
    path('manage/api/crowd/add/',            views.api_crowd_add,    name='api_crowd_add'),
    path('manage/api/crowd/<int:pk>/edit/',  views.api_crowd_edit,   name='api_crowd_edit'),
    path('manage/api/crowd/<int:pk>/delete/',views.api_crowd_delete, name='api_crowd_delete'),

    # SmokerAlert
    path('manage/api/smoker/add/',            views.api_smoker_add,    name='api_smoker_add'),
    path('manage/api/smoker/<int:pk>/edit/',  views.api_smoker_edit,   name='api_smoker_edit'),
    path('manage/api/smoker/<int:pk>/delete/',views.api_smoker_delete, name='api_smoker_delete'),

    # PassportEvent
    path('manage/api/passport/add/',            views.api_passport_add,    name='api_passport_add'),
    path('manage/api/passport/<int:pk>/edit/',  views.api_passport_edit,   name='api_passport_edit'),
    path('manage/api/passport/<int:pk>/delete/',views.api_passport_delete, name='api_passport_delete'),

    # ── External REST API (for remote AI models) ──────────────────────────────
    # Public ingest endpoints — authenticated by X-API-Key header, CSRF-exempt
    path('api/v1/passport/alert/', views.api_passport_ingest, name='api_passport_ingest'),
    path('api/v1/crowd/alert/',    views.api_crowd_ingest,    name='api_crowd_ingest'),
    path('api/v1/smoker/alert/',   views.api_smoker_ingest,   name='api_smoker_ingest'),

    # Admin key management (requires admin session)
    path('manage/api/generate-key/',         views.api_generate_key, name='api_generate_key'),
    path('manage/api/keys/',                 views.api_list_keys,    name='api_list_keys'),
    path('manage/api/keys/<int:pk>/revoke/', views.api_revoke_key,   name='api_revoke_key'),
]
