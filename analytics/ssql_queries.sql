-- Detect more than 5 failed logins within 5 minutes

SELECT
    machine_id,
    COUNT(*) AS failed_attempts,
    MIN(event_time) AS start_time,
    MAX(event_time) AS end_time
FROM auth_events
WHERE event_category = 'LOGIN_FAILURE'
GROUP BY machine_id
HAVING COUNT(*) >= 5;

-- Detect failed login followed by success on same machine

SELECT
    a.machine_id,
    a.event_time AS failed_time,
    b.event_time AS success_time
FROM auth_events a
JOIN auth_events b
ON a.machine_id = b.machine_id
WHERE a.event_category = 'LOGIN_FAILURE'
  AND b.event_category = 'LOGIN_SUCCESS'
  AND b.event_time > a.event_time;

-- Detect high privilege check frequency

SELECT
    machine_id,
    COUNT(*) AS privilege_events
FROM auth_events
WHERE event_category = 'PRIVILEGE_CHECK'
GROUP BY machine_id
HAVING COUNT(*) > 20;

-- Logins outside working hours (before 6 AM or after 10 PM)

SELECT
    machine_id,
    event_time
FROM auth_events
WHERE event_category = 'LOGIN_SUCCESS'
  AND (
        CAST(strftime('%H', event_time) AS INTEGER) < 6
        OR
        CAST(strftime('%H', event_time) AS INTEGER) > 22
      );

-- High number of auth events in short time

SELECT
    machine_id,
    COUNT(*) AS total_events
FROM auth_events
GROUP BY machine_id
HAVING COUNT(*) > 50;

