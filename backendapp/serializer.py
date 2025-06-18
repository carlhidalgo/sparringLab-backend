from rest_framework import serializers
from .models import SparringReservation

class SparringReservationSerializer(serializers.ModelSerializer):
    class Meta:
        model = SparringReservation
        fields = '__all__'