#!/bin/sh

# Configure perms
chmod a+w /svc/mount/users.db

# Start up the service
su -c "python3 /svc/mount/app.py" user &
sleep 1

# Check the health in a loop
health=1
while [[ "$health" == "1" ]]
do
    # Wait a bit to stabalize
    sleep 10
    # Run the health check script (as root)
    health=$(/root/health.sh)
    # Save the result to the result file
    echo $health > /svc/health.txt
    # Ensure the correct perms
    chmod og-wx /svc/health.txt
done

wait
