-- Detailed report on ping status per coputer per day (for the last 7 days)
select ResourceGuid, CAST(timestamp as date), COUNT(*) as 'Ping tests', sum(CASE c.status when '1' then 1 else 0 end) as 'successful pings'
  from CWoC_Pinger_Event c
 where eventtype = 'ping'
   and timestamp > GETDATE() -7
 group by ResourceGuid, CAST(timestamp as date)
 order by resourceguid, CAST(timestamp as date) desc
 
-- Summary report of computer ping status of the last 7 days
select ResourceGuid, SUM([ping tests]), SUM([successful pings])
  from (
			select ResourceGuid, CAST(timestamp as date) as 'Date', COUNT(*) as 'Ping tests', sum(CASE c.status when '1' then 1 else 0 end) as 'successful pings'
			  from CWoC_Pinger_Event c
			 where eventtype = 'ping'
			   and timestamp > GETDATE() -7
			 group by ResourceGuid, CAST(timestamp as date)
		) t
 group by t.resourceguid
 order by t.resourceguid

-- Computers that are always on in the last 7 days
select ResourceGuid, SUM([ping tests]), SUM([successful pings]), MAX(t.date) as 'Latest event', CAST(getdate() as date) as 'Today'
  from (
			select ResourceGuid, CAST(timestamp as date) as 'Date', COUNT(*) as 'Ping tests', sum(CASE c.status when '1' then 1 else 0 end) as 'successful pings'
			  from CWoC_Pinger_Event c
			 where eventtype = 'ping'
			   and timestamp > GETDATE() -7
			 group by ResourceGuid, CAST(timestamp as date)
		) t
 group by t.resourceguid
having SUM([ping tests]) = SUM([successful pings])
   and SUM([ping tests]) > 3
   and (MAX(t.date) = CAST(getdate() -1 as date) or MAX(t.date) = CAST(getdate() as date))
 order by SUM([ping tests]) desc
