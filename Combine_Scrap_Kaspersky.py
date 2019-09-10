#Date - 9/9/2019
#Developer - K.Janarthanan
#scrapy runspider ./Combine_Scrap_Kaspersky.py -o <sample.json, .csv>
#To retrieve malware details from kaspersky database and the description of the threat


import scrapy


class Kaspersky_scraper(scrapy.Spider):
    name = "Kaspersky_Malware_DB"
    start_urls = ['https://threats.kaspersky.com/en/threat/?view=hierarchy']

    def parse(self, response):
       
        level1=response.css(".hierarchy_lvl1")
        
        for a in level1:

            level2=a.css(".hierarchy_lvl1 > .hierarchy_lvl2")

            if len(level2)==0:
                level3=a.css(".hierarchy_lvl1 > .hierarchy_lvl3")
            

                for c in level3:
                    level4=c.css(".hierarchy_lvl3 > .hierarchy_lvl4")

                    for d in level4:
                    
                        vLevel1=a.css(".hierarchy_lvl1 > a::text").extract_first()
                        vLevel2="None"
                        vLevel3=c.css(".hierarchy_lvl3 > a::text").extract_first()
                        vLevel4=d.css(".hierarchy_lvl4 > a::text").extract_first().strip()
                        vLink=d.css(".hierarchy_lvl4 > a::attr(href)").extract_first()

                        
                        answer={'Broad_Category': vLevel1,'Sub_category':vLevel2,'Platform':vLevel3,'Threat':vLevel4,'Link':vLink}
                        yield scrapy.Request(vLink,callback=self.parse_link,meta={'item': answer})
                        
            else:
                for b in level2:
                    level3=b.css(".hierarchy_lvl2 > .hierarchy_lvl3")

                    for c in level3:
                        level4=c.css(".hierarchy_lvl3 > .hierarchy_lvl4")

                        for d in level4:
                            
                            vLevel1=a.css(".hierarchy_lvl1 > a::text").extract_first()
                            vLevel2=b.css(".hierarchy_lvl2 > a::text").extract_first()
                            vLevel3=c.css(".hierarchy_lvl3 > a::text").extract_first()
                            vLevel4=d.css(".hierarchy_lvl4 > a::text").extract_first().strip()
                            vLink=d.css(".hierarchy_lvl4 > a::attr(href)").extract_first()

                            
                            answer={'Broad_Category': vLevel1,'Sub_category':vLevel2,'Platform':vLevel3,'Threat':vLevel4,'Link':vLink}
                            yield scrapy.Request(vLink,callback=self.parse_link,meta={'item': answer})
                            
        
    def parse_link(self,response):

        describe=str(response.css(".cell_two > p::text").extract()).rstrip() 

        item = response.meta['item']
        item['Description'] = describe
        yield item 
          


                