import base64
from django.shortcuts import redirect, render
import mysql.connector as sql
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

@csrf_protect
def registration(request):
    if request.method == "POST":
        # Connect to the database
        conn = sql.connect(host="localhost", user="root", password="Vaishu@04", database="smarthealth")
        cursor = conn.cursor()
        
        # Get the data from the form
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        cpassword = request.POST.get("cpassword")
        print(username, email, password, cpassword)
        
        # Check if password and confirm password match
        if password == cpassword:
            # Insert data into the database without saving cpassword
            cursor.execute("INSERT INTO registration (username, email, password, cpassword) VALUES (%s, %s, %s, %s)", (username, email, password, cpassword))
            conn.commit()
            message = "Registration successful!"
        else:
            # Display an error message if passwords do not match
            message = "Password and confirm password do not match."
        
        # Close the database connection
        cursor.close()
        conn.close()
        
        # Pass the message to the template
        return render(request, 'registration.html', {"message": message})
    
    return render(request, 'registration.html')

def home(request):
    print("User is authenticated:", request.user.is_authenticated)
    print("User username:", request.user.username)
   
    print(request.user.is_authenticated)
    return render(request,'home.html')

from django.contrib.auth import authenticate, login as auth_login  # For user authentication and login
from django.contrib import messages  # For displaying error or success messages

@csrf_protect
def login(request):
    error_message = ""
    
    if request.method == "POST":
        # Connect to the database
        try:
            conn = sql.connect(host="localhost", user="root", password="Vaishu@04", database="smarthealth")
            cursor = conn.cursor()
            
            # Get the data from the form
            username = request.POST.get("username")
            password = request.POST.get("password")
            
            print("Login attempt with username:", username, "and password:", password)  # Debugging print statement
            
            # Retrieve the user data from the database
            query = "SELECT password FROM registration WHERE username = %s"
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            
            if result:
                # If a record is found, check if the password matches
                db_password = result[0]
                print("Password in database:", db_password)  # Debugging print statement
                
                if db_password == password:
                    print("Login successful")  # Debugging print statement
                    # Clear any unread results to avoid errors when closing
                    cursor.fetchall()  # Ensures all results are read
                    return redirect('logout')  # Redirect to home page on successful login
                else:
                    error_message = "Invalid password."
            else:
                error_message = "Username not found."
                
        except sql.Error as e:
            print("Database error:", e)
            error_message = "Database error. Please try again later."
        
        finally:
            # Ensure all results are processed before closing
            cursor.fetchall()  # Clears any remaining results
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    # Pass the error message to the template if login fails
    return render(request, 'login.html', {"error_message": error_message})

from django.http import HttpResponseForbidden

def csrf_failure(request, reason=""):
    return HttpResponseForbidden("Custom CSRF failure message.")

from django.shortcuts import render
from django.contrib.auth.decorators import login_required

from django.shortcuts import render
from io import BytesIO
import matplotlib.pyplot as plt
import base64

def healthInsights(request):
    analysis = None
    charts = {}
    recommendations = []

    if request.method == "POST":
        # Get user inputs
        try:
            heart_rate = int(request.POST.get("heart_rate"))
            oxygen_level = int(request.POST.get("oxygen_level"))
            blood_pressure = request.POST.get("blood_pressure")
            body_temperature = float(request.POST.get("body_temperature"))
            steps_taken = int(request.POST.get("steps_taken"))
            water_intake = float(request.POST.get("water_intake"))
            calories_burnt = int(request.POST.get("calories_burnt"))
        except ValueError as e:
            analysis = "Invalid input detected. Please enter valid data."
            return render(request, "health_insights.html", {
                "analysis": analysis,
                "charts": charts,
                "recommendations": recommendations
            })

        # Print inputs for debugging
        print("User Inputs:")
        print(f"Heart Rate: {heart_rate}, Oxygen Level: {oxygen_level}, Blood Pressure: {blood_pressure},")
        print(f"Body Temperature: {body_temperature}, Steps Taken: {steps_taken}, Water Intake: {water_intake}, Calories Burnt: {calories_burnt}")

        # Define normal ranges
        normal_heart_rate = (60, 100)
        normal_oxygen_level = 95
        normal_body_temperature = (36.1, 37.5)
        normal_steps_taken = 10000
        normal_water_intake = 2.5
        normal_calories_burnt = 400

        def generate_chart(parameter_name, normal_value, user_value):
            fig, ax = plt.subplots(figsize=(5, 3))
            ax.bar(["Normal", "Your Data"], [normal_value, user_value], color=['#00796b', '#ff5722'])
            ax.set_title(parameter_name)
            ax.set_ylabel("Values")
            ax.set_ylim(0, max(normal_value, user_value) + 10)
            plt.tight_layout()

            # Convert chart to base64
            buffer = BytesIO()
            plt.savefig(buffer, format="png")
            buffer.seek(0)
            image_png = buffer.getvalue()
            buffer.close()
            plt.close(fig)
            return base64.b64encode(image_png).decode('utf-8')

        # Generate charts for each parameter
        charts['heart_rate'] = generate_chart("Heart Rate (BPM)", 70, heart_rate)
        charts['oxygen_level'] = generate_chart("Oxygen Saturation (%)", 95, oxygen_level)
        charts['body_temperature'] = generate_chart("Body Temperature (°C)", 37.0, body_temperature)
        charts['steps_taken'] = generate_chart("Steps Taken", 10000, steps_taken)
        charts['water_intake'] = generate_chart("Water Intake (Liters)", 2.5, water_intake)
        charts['calories_burnt'] = generate_chart("Calories Burnt", 500, calories_burnt)
        # Provide recommendations based on inputs
        if heart_rate < normal_heart_rate[0] or heart_rate > normal_heart_rate[1]:
            recommendations.append(f"Your heart rate ({heart_rate} BPM) is outside the normal range ({normal_heart_rate[0]}-{normal_heart_rate[1]} BPM). Consider consulting a doctor.")
        
        if oxygen_level < normal_oxygen_level:
            recommendations.append(f"Your oxygen level ({oxygen_level}%) is below the normal range (>={normal_oxygen_level}%). Ensure proper breathing or seek medical advice if needed.")
        
        if body_temperature < normal_body_temperature[0] or body_temperature > normal_body_temperature[1]:
            recommendations.append(f"Your body temperature ({body_temperature}°C) is outside the normal range ({normal_body_temperature[0]}-{normal_body_temperature[1]}°C). Stay hydrated and rest.")

        if steps_taken < normal_steps_taken:
            recommendations.append(f"Your daily steps ({steps_taken}) are below the recommended target ({normal_steps_taken} steps). Try to be more physically active.")

        if water_intake < normal_water_intake:
            recommendations.append(f"Your daily water intake ({water_intake} liters) is below the recommended level ({normal_water_intake} liters). Increase your hydration.")

        if calories_burnt < normal_calories_burnt:
            recommendations.append(f"Your calories burnt ({calories_burnt}) are below the recommended minimum ({normal_calories_burnt} calories). Engage in more physical activities.")

        # If no issues, give a general recommendation
        if not recommendations:
            recommendations.append("All your parameters are within normal ranges. Keep up the good work!")

        # General analysis
        analysis = "Your health parameters have been analyzed. Please review the recommendations and charts."

    return render(request, "healthInsights.html", {
        "analysis": analysis,
        "charts": charts,
        "recommendations": recommendations
    })



from .models import wellness
from django.db.models import Q

def wellness_view(request):
    # Search functionality
    search_query = request.GET.get('search', '')
    if search_query:
        transactions = wellness.objects.filter(
            Q(category__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    else:
        transactions = wellness.objects.all()
 
    # Pass transactions to the template
    return render(request, 'wellness.html', {
        'transactions': transactions,
        'search_query': search_query
    })

from .models import Doctor, Patient, Appointment  # Import the Appointment model
 

def dashboard(request):
    # Get counts for doctors, patients, and appointments
    total_doctors = Doctor.objects.count()
    total_patients = Patient.objects.count()
    total_appointments = Appointment.objects.count()  # Count of appointments
 
    # Fetch recent doctors, patients, and appointments with relevant fields
    recent_doctors = Doctor.objects.all().order_by('-id')[:3]  # Limit to the latest 3 doctors
    recent_patients = Patient.objects.all().order_by('-id')[:3]  # Limit to the latest 3 patients
    # recent_appointments = Appointment.objects.all().order_by('-appointment_date')[:3]  # Latest 3 appointments
    recent_appointments = Appointment.objects.all().order_by('-appointment_date')[:3]  # Latest 3 appointments
 
    # Context to pass to the template
    context = {
        'total_doctors': total_doctors,
        'total_patients': total_patients,
        'total_appointments': total_appointments,
        'recent_doctors': recent_doctors,
        'recent_patients': recent_patients,
        'recent_appointments': recent_appointments,
    }
 
    return render(request, 'dashboard.html', context)
 

from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    logout(request)  # Clears the user's session
    print("Hi")
    return render(request, 'logout.html')  # Redirect to the home page or any other page

