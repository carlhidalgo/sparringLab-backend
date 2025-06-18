# forms.py

from django import forms
from django.core.exceptions import ValidationError
from .models import SparringReservation

class SparringReservationForm(forms.ModelForm):
    class Meta:
        model = SparringReservation
        fields = ['requester', 'opponent', 'gym', 'date', 'time', 'notes']

    def clean(self):
        cleaned_data = super().clean()
        requester = cleaned_data.get("requester")
        opponent = cleaned_data.get("opponent")
        date = cleaned_data.get("date")
        time = cleaned_data.get("time")

        if not (requester and opponent and date and time):
            return cleaned_data  # Required fields are missing; skip this check

        # Check if either boxer is already scheduled at that date + time
        conflicts = SparringReservation.objects.filter(
            date=date,
            time=time
        ).filter(
            models.Q(requester=requester) | models.Q(opponent=requester) |
            models.Q(requester=opponent) | models.Q(opponent=opponent)
        )

        if conflicts.exists():
            raise ValidationError("One of the boxers is already scheduled at this date and time.")

        return cleaned_data
