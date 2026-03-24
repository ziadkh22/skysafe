from django.db import models


class UserProfile(models.Model):
    # Personal Info
    name        = models.CharField(max_length=150)
    email       = models.EmailField(unique=True)
    phone       = models.CharField(max_length=30)
    dob         = models.DateField()
    gender      = models.CharField(max_length=10)
    address     = models.CharField(max_length=255)

    # Job Info
    job_title   = models.CharField(max_length=100)
    nationality = models.CharField(max_length=100)

    # File Uploads
    resume      = models.FileField(upload_to='uploads/resumes/', blank=True, null=True)
    national_id = models.FileField(upload_to='uploads/national_ids/', blank=True, null=True)
    photo       = models.ImageField(upload_to='uploads/photos/', blank=True, null=True)

    # Credentials
    username    = models.CharField(max_length=50, unique=True)
    password    = models.CharField(max_length=255)   # stored hashed

    created_at  = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.username} ({self.job_title})"


class ManagerWarning(models.Model):
    PRIORITY_CHOICES = [
        ('high',   'High Priority'),
        ('normal', 'Normal'),
    ]

    employee  = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='warnings')
    title     = models.CharField(max_length=200)
    message   = models.TextField()
    priority  = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='normal')
    sent_by   = models.CharField(max_length=100, default='Admin')
    sent_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-sent_at']

    def __str__(self):
        return f"[{self.priority.upper()}] {self.title} → {self.employee.username}"


# ─── DASHBOARD DATA MODELS ─────────────────────────────────────────────────────

class CyberThreat(models.Model):
    SEVERITY_CHOICES = [('HIGH', 'High'), ('MEDIUM', 'Medium'), ('LOW', 'Low')]
    severity   = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='MEDIUM')
    message    = models.CharField(max_length=300)
    created_at = models.DateTimeField(auto_now_add=True)
    is_new     = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.severity}] {self.message[:60]}"


class IoTDevice(models.Model):
    STATUS_CHOICES = [('ONLINE', 'Online'), ('OFFLINE', 'Offline'), ('WARNING', 'Warning')]
    device_name = models.CharField(max_length=150)
    status      = models.CharField(max_length=10, choices=STATUS_CHOICES, default='ONLINE')
    created_at  = models.DateTimeField(auto_now_add=True)
    is_new      = models.BooleanField(default=True)

    class Meta:
        ordering = ['device_name']

    def __str__(self):
        return f"{self.device_name} ({self.status})"


class CameraAccessLog(models.Model):
    user_display = models.CharField(max_length=100)  # e.g. "J.Doe (SKY-0872)"
    action       = models.CharField(max_length=10, choices=[('Accessed', 'Accessed'), ('Ended', 'Ended')], default='Accessed')
    feed_name    = models.CharField(max_length=150)
    created_at   = models.DateTimeField(auto_now_add=True)
    is_new       = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user_display} {self.action} {self.feed_name}"


class FireAlert(models.Model):
    SEVERITY_CHOICES = [('HIGH', 'High'), ('MEDIUM', 'Medium/Warn'), ('LOW', 'Low/Info')]
    severity   = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='MEDIUM')
    message    = models.CharField(max_length=300)
    created_at = models.DateTimeField(auto_now_add=True)
    is_new     = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.severity}] {self.message[:60]}"


class CrowdedGate(models.Model):
    CROWD_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH',     'High'),
        ('MODERATE', 'Moderate'),
        ('LOW',      'Low'),
    ]
    gate_name  = models.CharField(max_length=150)
    crowd_level = models.CharField(max_length=10, choices=CROWD_CHOICES, default='LOW')
    count      = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    is_new     = models.BooleanField(default=True)

    class Meta:
        ordering = ['-crowd_level', 'gate_name']

    def __str__(self):
        return f"{self.gate_name} — {self.crowd_level} ({self.count})"


class SmokerAlert(models.Model):
    SEVERITY_CHOICES = [('HIGH', 'Alert'), ('MEDIUM', 'Warning'), ('LOW', 'Info')]
    severity   = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='HIGH')
    message    = models.CharField(max_length=300)
    created_at = models.DateTimeField(auto_now_add=True)
    is_new     = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.severity}] {self.message[:60]}"


class PassportEvent(models.Model):
    STATUS_CHOICES = [('HIGH', 'Flagged'), ('MEDIUM', 'Warning'), ('LOW', 'OK')]
    passport_id = models.CharField(max_length=50)
    status      = models.CharField(max_length=10, choices=STATUS_CHOICES, default='LOW')
    message     = models.CharField(max_length=300)
    created_at  = models.DateTimeField(auto_now_add=True)
    is_new      = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.passport_id} [{self.status}]"


# ─── EXTERNAL API KEY (for remote AI model access) ─────────────────────────────

import secrets


class ExternalAPIKey(models.Model):
    name       = models.CharField(max_length=100, help_text="Friendly label, e.g. 'passport-ai-model'")
    key        = models.CharField(max_length=64, unique=True, editable=False)
    is_active  = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = secrets.token_hex(32)   # 64 hex chars
        super().save(*args, **kwargs)

    class Meta:
        verbose_name = "External API Key"

    def __str__(self):
        return f"{self.name} ({'active' if self.is_active else 'revoked'})"

