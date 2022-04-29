@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string)
{
    if(code == 404) {
      SumStats::observe("http_response_404", SumStats::Key($host = c$id$orig_h), SumStats::Observation($str=c$http$uri));
      SumStats::observe("http_response_404_all", SumStats::Key($host = c$id$orig_h), SumStats::Observation($str=c$http$uri));

    }
    SumStats::observe("http_response", SumStats::Key($host = c$id$orig_h), SumStats::Observation($str=c$http$uri));
}

event zeek_init()
{
	local r1 = SumStats::Reducer($stream="http_response", $apply=set(SumStats::SUM));
	local r2 = SumStats::Reducer($stream="http_response_404_all", $apply=set(SumStats::SUM));
	local r3 = SumStats::Reducer($stream="http_response_404",$apply=set(SumStats::UNIQUE));
	SumStats::create([$name = "output_result",
					  $epoch = 10mins,
					  $reducers = set(r1,r2,r3),
					  $epoch_result(ts:time, key: SumStats::Key, result: SumStats::Result) = 
						{
							local rall = result["http_response"];
							local r404_all = result["http_response_404_all"];
							local r404_uni = result["http_response_404"];
							
							# print fmt("%d %d %d %s %s", r404_all$num, r404_uni$unique, rall$num, r404_all$sum, rall$sum);
							# print fmt("%f", r404_all$sum/rall$sum);
							if(r404_all$num > 2 && r404_all$sum / rall$sum > 0.2)
							{
								if(r404_uni$unique / r404_all$sum > 0.5)
								{
									print fmt("%s is a scanner with %s scan attemps on %s urls", key$host, r404_all$num, r404_uni$unique);
								}
							}
						}]);
}
