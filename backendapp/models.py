from django.db import models

# GYM MODEL
class Gym(models.Model):
    name = models.CharField(max_length=255)
    location = models.CharField(max_length=255)

    def __str__(self):
        return self.name

# BOXER MODEL
class Boxer(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    birth_date = models.DateField()
    weight_class = models.CharField(max_length=100)
    record = models.CharField(max_length=50, blank=True)  # e.g., '15-2-0'
    is_active = models.BooleanField(default=True)
    gym_id = models.ForeignKey(Gym, on_delete=models.SET_NULL, null=True, related_name='boxers')

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

# COACH
class Coach(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    gym_id = models.ForeignKey(Gym, on_delete=models.SET_NULL, null=True, related_name='coaches')

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

# SESSION
class Session(models.Model):
    boxer_id = models.ForeignKey(Boxer, on_delete=models.CASCADE, related_name='sessions')
    coach_id = models.ForeignKey(Coach, on_delete=models.SET_NULL, null=True)
    type = models.CharField(max_length=100)  # e.g., Sparring, Pads
    date = models.DateField()
    duration_minutes = models.PositiveIntegerField()
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.session_type} - {self.boxer} ({self.date})"
    
class Fight(models.Model):
    boxer = models.ForeignKey(Boxer, on_delete=models.CASCADE, related_name='fights')
    opponent_name = models.CharField(max_length=255)
    event_name = models.CharField(max_length=255)
    fight_date = models.DateField()
    location = models.CharField(max_length=255)
    result = models.CharField(max_length=10, choices=[
        ('win', 'Win'),
        ('loss', 'Loss'),
        ('draw', 'Draw'),
        ('nc', 'No Contest')
    ])
    method = models.CharField(max_length=100, choices=[
        ('KO','ko'),
        ('TKO','tko'),
        ('UD','ud'),
        ('SD','sd')
    ])
    rounds = models.PositiveIntegerField()


    def __str__(self):
        return f"{self.boxer} vs {self.opponent_name} ({self.fight_date})"
    
class SparringReservation(models.Model):
    requester = models.ForeignKey('Boxer', on_delete=models.CASCADE, related_name='sparring_requests')
    opponent = models.ForeignKey('Boxer', on_delete=models.CASCADE, related_name='sparring_invites')
    gym = models.ForeignKey('Gym', on_delete=models.SET_NULL, null=True)
    date = models.DateField()
    time = models.TimeField()
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('cancelled', 'Cancelled')
    ], default='pending')
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.requester} vs {self.opponent} on {self.date} at {self.time}"

class Gimnasio(models.Model):
    nombre = models.CharField(max_length=255)
    direccion = models.CharField(max_length=255)
    ciudad = models.CharField(max_length=255)
    telefono = models.CharField(max_length=15)
    imagen_url = models.URLField(blank=True, null=True)

    def __str__(self):
        return self.nombre