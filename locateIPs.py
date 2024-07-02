import os
import requests
import json
import csv
import simplekml

# Initialize variables
arGeoResults = []
bVPNApi = False
strAPIKey = "MjQ0OTM6QTJZVWhFbkp5bjlud05nREVqb0ZOWU5LRDNQb2d2ZnU="  # Default API key

# Check if ipFile.txt file exists
if not os.path.exists("ipFile.txt"):
    print("Error. Please create a file called ipFile.txt and supply IP Addresses separated by new line breaks.")
    exit()

# Check if iphub-info.txt file exists for IPHub API key
if os.path.exists("iphub-info.txt"):
    bVPNApi = True
    with open("iphub-info.txt") as f:
        strAPIKey = f.readline().strip()
    print("iphub-info.txt API key exists. API will be used.")

def getVPNStatus(ip):
    """Function to retrieve VPN status using IPHub API"""
    strLink = "http://v2.api.iphub.info/ip/" + ip.strip()
    headers = {"X-Key": strAPIKey}
    response = requests.get(strLink, headers=headers, auth=None)
    strResponse = response.content.decode("utf-8")
    jsonResponse = json.loads(strResponse)
    return jsonResponse

# Read IP addresses from ipFile.txt
with open("ipFile.txt") as ipFile:
    for ip in ipFile:
        print("IP Address: " + ip.strip())
        response = requests.get("http://www.geoplugin.net/json.gp?ip=" + ip.strip())
        strResponse = response.content.decode("utf-8")

        if response.status_code == 200:
            try:
                jsonResponse = json.loads(strResponse)
                jsonResponse["isp"] = ""
                jsonResponse["block"] = ""
                arGeoResults.append(jsonResponse)
                if bVPNApi:
                    jsonVPN = getVPNStatus(ip)
                    jsonResponse["isp"] = jsonVPN.get("isp", "")
                    jsonResponse["block"] = jsonVPN.get("block", "")
            except json.JSONDecodeError:
                print(f"Error decoding JSON for IP {ip.strip()}. Response: {strResponse}")
        else:
            print(f"Error for IP {ip.strip()}. Status Code: {response.status_code}. Response: {strResponse}")

# Write geographic results to geo-coords.csv and geo-stats.csv
with open("geo-coords.csv", "w") as geoFile, open("geo-stats.csv", "w") as statsFile:
    strStatsTitle = "IP Address, Latitude, Longitude, City, Region, Country, Timezone, ISP, Blocked\n"
    statsFile.write(strStatsTitle)

    for jsonGeo in arGeoResults:
        # Use .get() with a default value to avoid NoneType errors
        ip_address = jsonGeo.get("geoplugin_request", "").strip()
        latitude = jsonGeo.get("geoplugin_latitude", "")
        longitude = jsonGeo.get("geoplugin_longitude", "")
        city = jsonGeo.get("geoplugin_city", "")
        region = jsonGeo.get("geoplugin_region", "")
        country = jsonGeo.get("geoplugin_countryName", "")
        timezone = jsonGeo.get("geoplugin_timezone", "")
        isp = jsonGeo.get("isp", "")
        block = jsonGeo.get("block", "")

        strGeoTitle = f'"{ip_address} {city}"'
        strGeo = f'{strGeoTitle},{latitude},{longitude}'
        strStats = f'{ip_address},{latitude},{longitude},{city},{region},{country},{timezone},{isp},{block}'

        print(strGeo)
        geoFile.write(strGeo + "\n")
        statsFile.write(strStats + "\n")

# Define desktop directory path for the non-root user
desktop_path = os.path.join("../../home/kali/Desktop")  # Replace 'username' with the actual non-root username

# Save KML file to the desktop
kml_file_path = os.path.join(desktop_path, 'locations.kml')

# Create a KML file with points and detailed descriptions for each location
with open('geo-coords.csv', 'r') as locationFile:
    kml = simplekml.Kml()
    reader = csv.reader(locationFile)
    
    # Collect coordinates for points
    coords = []
    for row in reader:
        if row[1].lower() != "none" and row[2].lower() != "none":  # Check that latitude and longitude are not "None"
            try:
                latitude = float(row[1])
                longitude = float(row[2])
                coords.append((longitude, latitude))
                
                # Add a point with detailed description
                pnt = kml.newpoint(name=row[0], coords=[(longitude, latitude)])
                pnt.description = f"IP Address: {row[0]}\nCity: {row[0].split()[-1]}\nLatitude: {latitude}\nLongitude: {longitude}"
                pnt.style.iconstyle.color = simplekml.Color.green  # Green color for points
            except ValueError:
                print(f"Skipping invalid row: {row}")
    
    if coords:
        line = kml.newlinestring(name="IP Path", coords=coords)
        line.style.linestyle.color = simplekml.Color.red
        line.style.linestyle.width = 3
    
    kml.save(kml_file_path)

print(f"Success! {kml_file_path} and geo-stats.csv have been created.")
