# Generated by Django 5.1.2 on 2024-10-27 17:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Registration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=150, unique=True)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('password', models.CharField(max_length=128)),
                ('phone_number', models.CharField(blank=True, max_length=15, null=True)),
            ],
        ),
        migrations.DeleteModel(
            name='MyModel',
        ),
    ]
