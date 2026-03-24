import json
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.utils.timezone import localtime

# Hardcoded admin credentials (stored as a hash for security)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD_HASH = 'pbkdf2_sha256$1200000$Cxe37lsLvX225DIVd2TAdc$akbUbmO4ltmKZpVfnNz0DyiJEdJWx6fX8JMX1IkkT+A='  # admin1234

from .models import (
    UserProfile, ManagerWarning,
    CyberThreat, IoTDevice, CameraAccessLog, FireAlert,
    CrowdedGate, SmokerAlert, PassportEvent,
    ExternalAPIKey,
)


# ─── helpers ───────────────────────────────────────────────────────────────────

def _require_admin(request):
    if not request.session.get('is_admin'):
        return redirect('admin_login')
    return None


def _fmt(dt):
    if dt is None:
        return ''
    t = localtime(dt)
    return t.strftime('%I:%M:%S %p')


def _json_ok(msg='Saved', **extra):
    return JsonResponse({'success': True, 'message': msg, **extra})


def _json_err(msg='Error', status=400):
    return JsonResponse({'success': False, 'message': msg}, status=status)


# ─── LANDING / SIGNUP / LOGIN ──────────────────────────────────────────────────

def landing_view(request):
    return render(request, 'views/landing.html')


def signup_view(request):
    if request.method == 'POST':
        name             = request.POST.get('name', '').strip()
        email            = request.POST.get('email', '').strip()
        phone            = request.POST.get('phone', '').strip()
        dob              = request.POST.get('dob', '').strip()
        gender           = request.POST.get('gender', '').strip()
        address          = request.POST.get('address', '').strip()
        job_title        = request.POST.get('job-title', '').strip()
        nationality      = request.POST.get('nationality', '').strip()
        username         = request.POST.get('username', '').strip()
        password         = request.POST.get('password', '').strip()
        confirm_password = request.POST.get('confirm-password', '').strip()

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'views/signup.html')

        if UserProfile.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken. Please choose another.')
            return render(request, 'views/signup.html')

        if UserProfile.objects.filter(email=email).exists():
            messages.error(request, 'An account with this email already exists.')
            return render(request, 'views/signup.html')

        user = UserProfile(
            name=name, email=email, phone=phone, dob=dob,
            gender=gender, address=address, job_title=job_title,
            nationality=nationality, username=username,
            password=make_password(password),
        )
        if 'resume' in request.FILES:
            user.resume = request.FILES['resume']
        if 'national-id' in request.FILES:
            user.national_id = request.FILES['national-id']
        if 'photo' in request.FILES:
            user.photo = request.FILES['photo']
        user.save()
        messages.success(request, 'Account created successfully! Please log in.')
        return redirect('login')

    return render(request, 'views/signup.html')


def login_view(request):
    if request.method == 'POST':
        identifier = request.POST.get('username', '').strip()
        password   = request.POST.get('password', '').strip()

        user = None
        try:
            user = UserProfile.objects.get(username=identifier)
        except UserProfile.DoesNotExist:
            try:
                user = UserProfile.objects.get(email=identifier)
            except UserProfile.DoesNotExist:
                pass

        if user is None or not check_password(password, user.password):
            messages.error(request, 'Invalid username or password. Please try again.')
            return render(request, 'views/login.html')

        request.session['user_id']     = user.id
        request.session['username']    = user.username
        request.session['name']        = user.name
        request.session['job_title']   = user.job_title
        request.session['email']       = user.email
        request.session['phone']       = user.phone
        request.session['dob']         = str(user.dob)
        request.session['gender']      = user.gender
        request.session['address']     = user.address
        request.session['nationality'] = user.nationality
        request.session['photo_url']   = user.photo.url if user.photo else ''
        return redirect('employee')

    return render(request, 'views/login.html')


def employee_view(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    try:
        user = UserProfile.objects.get(id=user_id)
    except UserProfile.DoesNotExist:
        request.session.flush()
        return redirect('login')

    context = {
        'employee_id': f"SKY-{user.id:04d}",
        'name':        user.name,
        'job_title':   user.job_title,
        'email':       user.email,
        'phone':       user.phone,
        'gender':      user.gender,
        'nationality': user.nationality,
        'dob':         user.dob,
        'address':     user.address,
        'photo_url':   user.photo.url if user.photo else '',
        'warnings':    user.warnings.all(),
    }
    return render(request, 'views/employee.html', context)


def logout_view(request):
    request.session.flush()
    return redirect('login')


# ─── ADMIN LOGIN ───────────────────────────────────────────────────────────────

def admin_login_view(request):
    if request.session.get('is_admin'):
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        if username == ADMIN_USERNAME and check_password(password, ADMIN_PASSWORD_HASH):
            request.session['is_admin'] = True
            request.session['admin_username'] = username
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid admin credentials. Access denied.')

    return render(request, 'views/admin_login.html')


def admin_logout_view(request):
    request.session.pop('is_admin', None)
    request.session.pop('admin_username', None)
    return redirect('admin_login')


# ─── DASHBOARD (admin-only, live DB data) ──────────────────────────────────────

def dashboard_view(request):
    guard = _require_admin(request)
    if guard:
        return guard

    def tagged(qs):
        items = list(qs)
        for obj in items:
            obj.fmt_time = _fmt(obj.created_at)
        return items

    context = {
        'cyber_threats':   tagged(CyberThreat.objects.all()[:10]),
        'iot_devices':     list(IoTDevice.objects.all()),
        'camera_logs':     tagged(CameraAccessLog.objects.all()[:8]),
        'fire_alerts':     tagged(FireAlert.objects.all()[:6]),
        'crowded_gates':   list(CrowdedGate.objects.all()),
        'smoker_alerts':   tagged(SmokerAlert.objects.all()[:6]),
        'passport_events': tagged(PassportEvent.objects.all()[:8]),
    }
    return render(request, 'views/dashboard.html', context)


# ─── ADMIN CONTROL PANEL ───────────────────────────────────────────────────────

def admin_control_view(request):
    guard = _require_admin(request)
    if guard:
        return guard

    context = {
        'cyber_threats':   CyberThreat.objects.all()[:50],
        'iot_devices':     IoTDevice.objects.all(),
        'camera_logs':     CameraAccessLog.objects.all()[:50],
        'fire_alerts':     FireAlert.objects.all()[:50],
        'crowded_gates':   CrowdedGate.objects.all(),
        'smoker_alerts':   SmokerAlert.objects.all()[:50],
        'passport_events': PassportEvent.objects.all()[:50],
    }
    return render(request, 'views/admin_control.html', context)


# ─── NOTIFICATIONS POLLING ─────────────────────────────────────────────────────

@require_GET
def api_notifications(request):
    if not request.session.get('is_admin'):
        return JsonResponse({'count': 0, 'items': []})

    new_items = []
    for Model, label in [
        (CyberThreat,     'Cyber Threat'),
        (FireAlert,       'Fire Alert'),
        (CrowdedGate,     'Crowded Gate'),
        (SmokerAlert,     'Smoker Alert'),
        (PassportEvent,   'Passport Event'),
        (IoTDevice,       'IoT Device'),
        (CameraAccessLog, 'Camera Log'),
    ]:
        qs = Model.objects.filter(is_new=True)
        for obj in qs:
            new_items.append({'label': label, 'text': str(obj)})
        qs.update(is_new=False)

    return JsonResponse({'count': len(new_items), 'items': new_items})


# ─── CyberThreat CRUD ─────────────────────────────────────────────────────────

@require_POST
def api_cyber_add(request):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = CyberThreat.objects.create(
        severity=request.POST.get('severity', 'MEDIUM'),
        message=request.POST.get('message', ''),
    )
    return _json_ok(id=obj.id)

@require_POST
def api_cyber_edit(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = get_object_or_404(CyberThreat, pk=pk)
    obj.severity = request.POST.get('severity', obj.severity)
    obj.message  = request.POST.get('message', obj.message)
    obj.save()
    return _json_ok()

@require_POST
def api_cyber_delete(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    get_object_or_404(CyberThreat, pk=pk).delete()
    return _json_ok('Deleted')


# ─── IoTDevice CRUD ──────────────────────────────────────────────────────────

@require_POST
def api_iot_add(request):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = IoTDevice.objects.create(
        device_name=request.POST.get('device_name', ''),
        status=request.POST.get('status', 'ONLINE'),
    )
    return _json_ok(id=obj.id)

@require_POST
def api_iot_edit(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = get_object_or_404(IoTDevice, pk=pk)
    obj.device_name = request.POST.get('device_name', obj.device_name)
    obj.status      = request.POST.get('status', obj.status)
    obj.save()
    return _json_ok()

@require_POST
def api_iot_delete(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    get_object_or_404(IoTDevice, pk=pk).delete()
    return _json_ok('Deleted')


# ─── CameraAccessLog CRUD ─────────────────────────────────────────────────────

@require_POST
def api_camera_add(request):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = CameraAccessLog.objects.create(
        user_display=request.POST.get('user_display', ''),
        action=request.POST.get('action', 'Accessed'),
        feed_name=request.POST.get('feed_name', ''),
    )
    return _json_ok(id=obj.id)

@require_POST
def api_camera_edit(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = get_object_or_404(CameraAccessLog, pk=pk)
    obj.user_display = request.POST.get('user_display', obj.user_display)
    obj.action       = request.POST.get('action', obj.action)
    obj.feed_name    = request.POST.get('feed_name', obj.feed_name)
    obj.save()
    return _json_ok()

@require_POST
def api_camera_delete(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    get_object_or_404(CameraAccessLog, pk=pk).delete()
    return _json_ok('Deleted')


# ─── FireAlert CRUD ───────────────────────────────────────────────────────────

@require_POST
def api_fire_add(request):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = FireAlert.objects.create(
        severity=request.POST.get('severity', 'MEDIUM'),
        message=request.POST.get('message', ''),
    )
    return _json_ok(id=obj.id)

@require_POST
def api_fire_edit(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = get_object_or_404(FireAlert, pk=pk)
    obj.severity = request.POST.get('severity', obj.severity)
    obj.message  = request.POST.get('message', obj.message)
    obj.save()
    return _json_ok()

@require_POST
def api_fire_delete(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    get_object_or_404(FireAlert, pk=pk).delete()
    return _json_ok('Deleted')


# ─── CrowdedGate CRUD ─────────────────────────────────────────────────────────

@require_POST
def api_crowd_add(request):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = CrowdedGate.objects.create(
        gate_name=request.POST.get('gate_name', ''),
        crowd_level=request.POST.get('crowd_level', 'LOW'),
        count=int(request.POST.get('count', 0)),
    )
    return _json_ok(id=obj.id)

@require_POST
def api_crowd_edit(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = get_object_or_404(CrowdedGate, pk=pk)
    obj.gate_name   = request.POST.get('gate_name', obj.gate_name)
    obj.crowd_level = request.POST.get('crowd_level', obj.crowd_level)
    obj.count       = int(request.POST.get('count', obj.count))
    obj.save()
    return _json_ok()

@require_POST
def api_crowd_delete(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    get_object_or_404(CrowdedGate, pk=pk).delete()
    return _json_ok('Deleted')


# ─── SmokerAlert CRUD ─────────────────────────────────────────────────────────

@require_POST
def api_smoker_add(request):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = SmokerAlert.objects.create(
        severity=request.POST.get('severity', 'HIGH'),
        message=request.POST.get('message', ''),
    )
    return _json_ok(id=obj.id)

@require_POST
def api_smoker_edit(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = get_object_or_404(SmokerAlert, pk=pk)
    obj.severity = request.POST.get('severity', obj.severity)
    obj.message  = request.POST.get('message', obj.message)
    obj.save()
    return _json_ok()

@require_POST
def api_smoker_delete(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    get_object_or_404(SmokerAlert, pk=pk).delete()
    return _json_ok('Deleted')


# ─── PassportEvent CRUD ───────────────────────────────────────────────────────

@require_POST
def api_passport_add(request):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = PassportEvent.objects.create(
        passport_id=request.POST.get('passport_id', ''),
        status=request.POST.get('status', 'LOW'),
        message=request.POST.get('message', ''),
    )
    return _json_ok(id=obj.id)

@require_POST
def api_passport_edit(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    obj = get_object_or_404(PassportEvent, pk=pk)
    obj.passport_id = request.POST.get('passport_id', obj.passport_id)
    obj.status      = request.POST.get('status', obj.status)
    obj.message     = request.POST.get('message', obj.message)
    obj.save()
    return _json_ok()

@require_POST
def api_passport_delete(request, pk):
    if not request.session.get('is_admin'): return _json_err('Forbidden', 403)
    get_object_or_404(PassportEvent, pk=pk).delete()
    return _json_ok('Deleted')


# ─── ADMIN EMPLOYEE MANAGEMENT ─────────────────────────────────────────────────

def admin_employees_view(request):
    guard = _require_admin(request)
    if guard: return guard

    query = request.GET.get('q', '').strip()
    employees = UserProfile.objects.all().order_by('name')
    if query:
        employees = (employees.filter(name__icontains=query) |
                     employees.filter(email__icontains=query) |
                     employees.filter(job_title__icontains=query))

    return render(request, 'views/admin_employees.html', {
        'employees': employees, 'query': query,
    })


def admin_edit_employee_view(request, pk):
    guard = _require_admin(request)
    if guard: return guard

    employee = get_object_or_404(UserProfile, pk=pk)

    if request.method == 'POST':
        employee.name        = request.POST.get('name', employee.name).strip()
        employee.email       = request.POST.get('email', employee.email).strip()
        employee.phone       = request.POST.get('phone', employee.phone).strip()
        employee.job_title   = request.POST.get('job_title', employee.job_title).strip()
        employee.address     = request.POST.get('address', employee.address).strip()
        employee.nationality = request.POST.get('nationality', employee.nationality).strip()
        employee.gender      = request.POST.get('gender', employee.gender).strip()
        dob_val = request.POST.get('dob', '').strip()
        if dob_val:
            employee.dob = dob_val
        employee.save()
        messages.success(request, f"Employee '{employee.name}' updated successfully.")
        return redirect('admin_employees')

    return render(request, 'views/admin_employees.html', {
        'edit_employee': employee,
        'employees':     UserProfile.objects.all().order_by('name'),
        'query':         '',
    })


def admin_send_warning_view(request, pk):
    guard = _require_admin(request)
    if guard: return guard

    if request.method == 'POST':
        employee = get_object_or_404(UserProfile, pk=pk)
        title    = request.POST.get('title', '').strip()
        msg      = request.POST.get('message', '').strip()
        priority = request.POST.get('priority', 'normal')

        if title and msg:
            ManagerWarning.objects.create(
                employee=employee, title=title, message=msg,
                priority=priority, sent_by='Admin',
            )
            messages.success(request, f"Warning sent to {employee.name}.")
        else:
            messages.error(request, 'Title and message are required.')

    return redirect('admin_employees')


# ─── EXTERNAL REST API — Passport Recognition (AI model → Dashboard) ───────────

from django.views.decorators.csrf import csrf_exempt
from django.utils.timezone import now as tz_now


@csrf_exempt
def api_passport_ingest(request):
    """
    Public JSON endpoint for remote AI models.
    POST /api/v1/passport/alert/
    Headers: X-API-Key: <key>   Content-Type: application/json
    Body:    {"passport_id": "EG-001", "status": "HIGH", "message": "...", "confidence": 0.97}
    """
    # CORS preflight
    if request.method == 'OPTIONS':
        resp = JsonResponse({'ok': True})
        resp['Access-Control-Allow-Origin']  = '*'
        resp['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
        resp['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return resp

    if request.method != 'POST':
        return _cors(JsonResponse({'success': False, 'error': 'POST required'}, status=405))

    # ── Authenticate ──────────────────────────────────────────────────────────
    api_key = request.headers.get('X-API-Key', '').strip()
    if not api_key:
        return _cors(JsonResponse({'success': False, 'error': 'Missing X-API-Key header'}, status=401))

    try:
        key_obj = ExternalAPIKey.objects.get(key=api_key, is_active=True)
    except ExternalAPIKey.DoesNotExist:
        return _cors(JsonResponse({'success': False, 'error': 'Invalid or revoked API key'}, status=403))

    # ── Parse JSON body ───────────────────────────────────────────────────────
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return _cors(JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400))

    passport_id = str(body.get('passport_id', '')).strip()
    status      = str(body.get('status', 'LOW')).strip().upper()
    message     = str(body.get('message', '')).strip()
    confidence  = body.get('confidence')   # optional float — stored in message if provided

    # ── Validate ──────────────────────────────────────────────────────────────
    valid_statuses = ('HIGH', 'MEDIUM', 'LOW')
    if not passport_id:
        return _cors(JsonResponse({'success': False, 'error': 'passport_id is required'}, status=400))
    if status not in valid_statuses:
        return _cors(JsonResponse({'success': False, 'error': f'status must be one of {valid_statuses}'}, status=400))
    if not message:
        return _cors(JsonResponse({'success': False, 'error': 'message is required'}, status=400))

    # Append confidence score to message if provided
    if confidence is not None:
        try:
            message = f"{message} (confidence: {float(confidence):.0%})"
        except (TypeError, ValueError):
            pass

    # ── Save ──────────────────────────────────────────────────────────────────
    event = PassportEvent.objects.create(
        passport_id=passport_id,
        status=status,
        message=message,
        is_new=True,     # triggers notification bell on dashboard
    )

    resp = JsonResponse({
        'success':     True,
        'id':          event.id,
        'passport_id': event.passport_id,
        'status':      event.status,
        'received_at': tz_now().isoformat(),
    }, status=201)
    return _cors(resp)


def _cors(response):
    """Attach CORS headers to any response so remote callers always get them."""
    response['Access-Control-Allow-Origin']  = '*'
    response['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
    return response


# ─── EXTERNAL REST API — Crowded Gate Detection (AI model → Dashboard) ──────────

@csrf_exempt
def api_crowd_ingest(request):
    """
    Public JSON endpoint for remote AI models.
    POST /api/v1/crowd/alert/
    Headers: X-API-Key: <key>   Content-Type: application/json
    Body:    {"gate_name": "Gate A", "crowd_level": "HIGH", "count": 120, "confidence": 0.95}
    """
    # CORS preflight
    if request.method == 'OPTIONS':
        resp = JsonResponse({'ok': True})
        resp['Access-Control-Allow-Origin']  = '*'
        resp['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
        resp['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return resp

    if request.method != 'POST':
        return _cors(JsonResponse({'success': False, 'error': 'POST required'}, status=405))

    # ── Authenticate ──────────────────────────────────────────────────────────
    api_key = request.headers.get('X-API-Key', '').strip()
    if not api_key:
        return _cors(JsonResponse({'success': False, 'error': 'Missing X-API-Key header'}, status=401))

    try:
        ExternalAPIKey.objects.get(key=api_key, is_active=True)
    except ExternalAPIKey.DoesNotExist:
        return _cors(JsonResponse({'success': False, 'error': 'Invalid or revoked API key'}, status=403))

    # ── Parse JSON body ───────────────────────────────────────────────────────
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return _cors(JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400))

    gate_name   = str(body.get('gate_name', '')).strip()
    crowd_level = str(body.get('crowd_level', 'LOW')).strip().upper()
    count       = body.get('count', 0)
    confidence  = body.get('confidence')   # optional float

    # ── Validate ──────────────────────────────────────────────────────────────
    valid_levels = ('CRITICAL', 'HIGH', 'MODERATE', 'LOW')
    if not gate_name:
        return _cors(JsonResponse({'success': False, 'error': 'gate_name is required'}, status=400))
    if crowd_level not in valid_levels:
        return _cors(JsonResponse({'success': False, 'error': f'crowd_level must be one of {valid_levels}'}, status=400))
    try:
        count = int(count)
        if count < 0:
            raise ValueError
    except (TypeError, ValueError):
        return _cors(JsonResponse({'success': False, 'error': 'count must be a non-negative integer'}, status=400))

    # Build optional confidence note
    note = ''
    if confidence is not None:
        try:
            note = f' (confidence: {float(confidence):.0%})'
        except (TypeError, ValueError):
            pass

    # ── Save ──────────────────────────────────────────────────────────────────
    event = CrowdedGate.objects.create(
        gate_name=gate_name,
        crowd_level=crowd_level,
        count=count,
        is_new=True,
    )

    resp = JsonResponse({
        'success':     True,
        'id':          event.id,
        'gate_name':   event.gate_name,
        'crowd_level': event.crowd_level,
        'count':       event.count,
        'note':        note,
        'received_at': tz_now().isoformat(),
    }, status=201)
    return _cors(resp)


# ─── EXTERNAL REST API — Smoker Detection (AI model → Dashboard) ────────────────

@csrf_exempt
def api_smoker_ingest(request):
    """
    Public JSON endpoint for remote AI models.
    POST /api/v1/smoker/alert/
    Headers: X-API-Key: <key>   Content-Type: application/json
    Body:    {"severity": "HIGH", "message": "Smoking detected at Gate B", "confidence": 0.91}
    """
    # CORS preflight
    if request.method == 'OPTIONS':
        resp = JsonResponse({'ok': True})
        resp['Access-Control-Allow-Origin']  = '*'
        resp['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
        resp['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return resp

    if request.method != 'POST':
        return _cors(JsonResponse({'success': False, 'error': 'POST required'}, status=405))

    # ── Authenticate ──────────────────────────────────────────────────────────
    api_key = request.headers.get('X-API-Key', '').strip()
    if not api_key:
        return _cors(JsonResponse({'success': False, 'error': 'Missing X-API-Key header'}, status=401))

    try:
        ExternalAPIKey.objects.get(key=api_key, is_active=True)
    except ExternalAPIKey.DoesNotExist:
        return _cors(JsonResponse({'success': False, 'error': 'Invalid or revoked API key'}, status=403))

    # ── Parse JSON body ───────────────────────────────────────────────────────
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return _cors(JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400))

    severity   = str(body.get('severity', 'HIGH')).strip().upper()
    message    = str(body.get('message', '')).strip()
    confidence = body.get('confidence')   # optional float

    # ── Validate ──────────────────────────────────────────────────────────────
    valid_severities = ('HIGH', 'MEDIUM', 'LOW')
    if severity not in valid_severities:
        return _cors(JsonResponse({'success': False, 'error': f'severity must be one of {valid_severities}'}, status=400))
    if not message:
        return _cors(JsonResponse({'success': False, 'error': 'message is required'}, status=400))

    # Append confidence score to message if provided
    if confidence is not None:
        try:
            message = f'{message} (confidence: {float(confidence):.0%})'
        except (TypeError, ValueError):
            pass

    # ── Save ──────────────────────────────────────────────────────────────────
    event = SmokerAlert.objects.create(
        severity=severity,
        message=message,
        is_new=True,
    )

    resp = JsonResponse({
        'success':     True,
        'id':          event.id,
        'severity':    event.severity,
        'message':     event.message,
        'received_at': tz_now().isoformat(),
    }, status=201)
    return _cors(resp)


@require_GET
def api_generate_key(request):
    """
    Admin-only: generate a new ExternalAPIKey and return it once.
    GET /manage/api/generate-key/?name=passport-ai-model
    """
    if not request.session.get('is_admin'):
        return JsonResponse({'success': False, 'error': 'Admin session required'}, status=403)

    name = request.GET.get('name', 'ai-model').strip() or 'ai-model'
    key_obj = ExternalAPIKey(name=name)
    key_obj.save()  # auto-generates key in model.save()

    return JsonResponse({
        'success':    True,
        'name':       key_obj.name,
        'key':        key_obj.key,
        'note':       'Copy this key now — it will not be shown again in full.',
        'created_at': key_obj.created_at.isoformat(),
    })


@require_GET
def api_list_keys(request):
    """Admin-only: list all API keys (masked) and allow revocation."""
    if not request.session.get('is_admin'):
        return JsonResponse({'success': False, 'error': 'Admin session required'}, status=403)

    keys = ExternalAPIKey.objects.all().order_by('-created_at').values(
        'id', 'name', 'is_active', 'created_at'
    )
    # Mask: only show first 8 chars of the key
    result = []
    for k_obj in ExternalAPIKey.objects.all().order_by('-created_at'):
        result.append({
            'id':         k_obj.id,
            'name':       k_obj.name,
            'key_prefix': k_obj.key[:8] + '...',
            'is_active':  k_obj.is_active,
            'created_at': k_obj.created_at.isoformat(),
        })
    return JsonResponse({'success': True, 'keys': result})


@require_POST
def api_revoke_key(request, pk):
    """Admin-only: deactivate (revoke) an API key by id."""
    if not request.session.get('is_admin'):
        return JsonResponse({'success': False, 'error': 'Admin session required'}, status=403)

    key_obj = get_object_or_404(ExternalAPIKey, pk=pk)
    key_obj.is_active = False
    key_obj.save()
    return JsonResponse({'success': True, 'message': f"Key '{key_obj.name}' revoked."})
