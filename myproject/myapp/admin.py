from django.contrib import admin
from .models import Registration, wellness
from .models import Doctor,Patient,Appointment
admin.site.register(Registration)
admin.site.register(Doctor)
admin.site.register(Patient)
admin.site.register(Appointment)
admin.site.register(wellness)