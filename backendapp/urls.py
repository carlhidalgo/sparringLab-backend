from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter
from .views import api_login,api_register,api_insert_gimnasio,obtener_clases,api_reservar_ring,api_create_blog,api_get_blogs,api_create_rutina,api_get_rutinas,api_update_user,api_delete_user,api_get_role,api_list_users,admin_update_user,api_verify_token,admin_delete_user,api_insert_gimnasio,api_list_gimnasios,api_update_gimnasio,api_delete_gimnasio,api_update_rutina,api_delete_rutina,api_listar_reservas,api_modificar_reserva,api_eliminar_reserva,crear_pago,pago_exitoso,start_payment_process,generate_transaction_token,complete_payment
from .views import CrearTorneoView,ListarTorneosView

router = DefaultRouter()


urlpatterns = [
    path('api/login/', api_login),
    path('api/register/', api_register),
    path('api/update_user/', api_update_user, name='api_update_user'),
    path('api/delete_user/', api_delete_user, name='delete_user'),
    path('api/gimnasios/', api_list_gimnasios),
    path('api/clases/', obtener_clases),
    path('api/reserva_ring',api_reservar_ring),
    path('api/reservas/listar/', api_listar_reservas, name='listar_reservas'),
    path('api/reservas/modificar/', api_modificar_reserva, name='modificar_reserva'),
    path('api/reservas/eliminar/', api_eliminar_reserva, name='eliminar_reserva'),
    path('api/create-blog/', api_create_blog, name='create_blog'),
    path('api/blogs/', api_get_blogs, name='api_get_blogs'),
    path('api/create_rutina', api_create_rutina, name='api_create_rutina'),
    path('api/get_rutina', api_get_rutinas, name='api_get_rutina'),
    path('api/get-role/', api_get_role, name='api_get_role'),
    path('api/verify_token/', api_verify_token, name='verify_token'),
    path('api/users/',api_list_users, name='api_list_users'),
    path('api/admin-update-user/', admin_update_user, name='admin_update_user'),
    path('api/admin-delete-user/', admin_delete_user, name='admin_delete_user'),
    path('api/gimnasios/listar/', api_list_gimnasios, name='listar_gimnasios'),
    path('api/gimnasios/crear/', api_insert_gimnasio, name='crear_gimnasio'),
    path('api/gimnasios/actualizar/', api_update_gimnasio, name='actualizar_gimnasio'),
    path('api/gimnasios/eliminar/', api_delete_gimnasio, name='eliminar_gimnasio'),
    path('api/update_rutina', api_update_rutina, name='api_update_rutina'),
    path('api/delete_rutina', api_delete_rutina, name='api_delete_rutina'),
    path('api/crear-pago/', crear_pago, name='crear_pago'),
    path('api/start_payment_process/', start_payment_process, name='start_payment_process'),
    path('api/generate_transaction_token/', generate_transaction_token, name='generate_transaction_token'),
    path('api/complete_payment/', complete_payment, name='complete_payment'),
    path('api/pago_exitoso/', pago_exitoso, name='pago_exitoso'),
    path('api/crear-torneo/', CrearTorneoView.as_view(), name='crear_torneo'),
    path('api/torneo/', ListarTorneosView.as_view(), name='lista_torneo'),
]
