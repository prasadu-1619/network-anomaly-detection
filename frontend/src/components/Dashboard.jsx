import React, { useState, useEffect, useMemo } from 'react';
import { BentoBox, BentoHeader } from './ui/Bento';
import { StatCard } from './StatCard';
import { useInterval } from '../useInterval';
import { MapPin, PieChart as PieChartIcon, TrendingUp, Target, Brain } from 'lucide-react';
import {
  ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip,
  ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line, Area, AreaChart,
  BarChart, Bar, ReferenceLine, Legend, ComposedChart
} from 'recharts';

const API_BASE = "http://127.0.0.1:8050";
const REFRESH_INTERVAL = 2000;

const COLORS = ['#00d4ff', '#00ff88', '#ffa500', '#ff0055'];

export function Dashboard() {
  const [stats, setStats] = useState(null);
  const [plotData, setPlotData] = useState(null);
  const [config, setConfig] = useState(null);
  const [error, setError] = useState(false);

  const fetchData = async () => {
    try {
      const [statsRes, plotRes, configRes] = await Promise.all([
        fetch(`${API_BASE}/api/stats`),
        fetch(`${API_BASE}/api/plot_data`),
        fetch(`${API_BASE}/api/config`)
      ]);
      setStats(await statsRes.json());
      setPlotData(await plotRes.json());
      setConfig(await configRes.json());
      setError(false);
    } catch (err) {
      setError(true);
    }
  };

  useInterval(fetchData, REFRESH_INTERVAL);
  useEffect(() => { fetchData() }, []);

  const formattedData = useMemo(() => {
    if (!plotData || !plotData.timestamp || plotData.timestamp.length === 0) return [];
    return plotData.timestamp.map((ts, i) => ({
      timestamp: ts,
      timeLabel: new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      bytes_sent: plotData.bytes_sent[i],
      bytes_received: plotData.bytes_received[i],
      packets: plotData.packets[i],
      anomaly: plotData.anomaly[i],
      anomaly_score: plotData.anomaly_score[i],
      protocol: plotData.protocol[i],
    }));
  }, [plotData]);

  const protocols = useMemo(() => {
    if (!formattedData.length) return [];
    const counts = formattedData.reduce((acc, curr) => {
      acc[curr.protocol] = (acc[curr.protocol] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 5);
  }, [formattedData]);

  if (error || !stats) {
    return (
      <div className="flex items-center justify-center h-64 text-cyber-text">
        <p className="animate-pulse flex items-center gap-2">
          {error ? "⚠️ Backend offline or unreachable..." : "⏳ Waiting for network data..."}
        </p>
      </div>
    );
  }

  const threatRate = stats.total_packets > 0 ? (stats.anomaly_count / stats.total_packets * 100) : 0;
  const threshold = config?.anomaly_score_threshold || -0.1;

  // Custom tooltips
  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-cyber-dark/95 border border-cyber-accent/30 p-3 rounded-lg shadow-xl text-xs">
          <p className="text-gray-300 mb-2 font-mono">{label || payload[0].payload.timeLabel}</p>
          {payload.map((entry, index) => (
            <p key={index} style={{ color: entry.color }} className="font-semibold">
              {entry.name}: {typeof entry.value === 'number' ? entry.value.toFixed(2) : entry.value}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  const scatterNormal = formattedData.filter(d => d.anomaly === "No");
  const scatterAnomaly = formattedData.filter(d => d.anomaly === "Yes");

  const avgScore = formattedData.length ? (formattedData.reduce((s, c) => s + c.anomaly_score, 0) / formattedData.length) : 0;
  const latestScore = formattedData.length ? formattedData[formattedData.length - 1].anomaly_score : 0;
  const pktMean = formattedData.length ? (formattedData.reduce((s, c) => s + c.packets, 0) / formattedData.length) : 0;

  return (
    <div className="flex flex-col gap-4">
      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard title="Total Packets" value={stats.total_packets.toLocaleString()} icon="📊" valueColorClass="text-white drop-shadow-[0_0_10px_rgba(0,212,255,0.5)]" delay={0.1} />
        <StatCard title="Normal" value={stats.normal_count.toLocaleString()} icon="✅" valueColorClass="text-white drop-shadow-[0_0_10px_rgba(0,255,136,0.5)]" delay={0.2} />
        <StatCard title="Anomalies" value={stats.anomaly_count.toLocaleString()} icon="⚠️" valueColorClass="text-white drop-shadow-[0_0_10px_rgba(255,0,85,0.5)]" delay={0.3} />
        <StatCard title="Threat Rate" value={`${threatRate.toFixed(1)}%`} icon="📈" valueColorClass="text-white drop-shadow-[0_0_10px_rgba(255,165,0,0.5)]" delay={0.4} />
      </div>

      {/* Row 2: Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Scatter Mapping */}
        <BentoBox delay={0.5}>
          <BentoHeader title="Traffic Mapping" icon={MapPin} colorClasses="text-cyber-accent" tooltip="Sent vs Received bytes. Outliers indicate anomalies." />
          <div className="h-[300px] w-full">
            <ResponsiveContainer>
              <ScatterChart margin={{ top: 20, right: 20, bottom: 30, left: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="bytes_sent" type="number" name="Sent" unit="B" stroke="#a8b8d4" tick={{ fontSize: 11 }} label={{ value: "Bytes Sent", position: "insideBottom", offset: -20, fill: "#a8b8d4", fontSize: 12 }} />
                <YAxis dataKey="bytes_received" type="number" name="Received" unit="B" stroke="#a8b8d4" tick={{ fontSize: 11 }} label={{ value: "Bytes Received", angle: -90, position: "insideLeft", offset: -10, fill: "#a8b8d4", fontSize: 12 }} />
                <RechartsTooltip cursor={{ strokeDasharray: '3 3' }} content={<CustomTooltip />} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: 12, top: -10 }} />
                <Scatter name="Normal" data={scatterNormal} fill="#00ff88" opacity={0.6} shape="circle" isAnimationActive={false} />
                <Scatter name="Anomaly" data={scatterAnomaly} fill="#ff0055" shape="cross" isAnimationActive={false} />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </BentoBox>

        {/* Protocol Mix */}
        <BentoBox delay={0.6}>
          <BentoHeader title="Protocol Mix" icon={PieChartIcon} colorClasses="text-cyber-success" tooltip="Network protocol distribution based on active buffer window." />
          <div className="h-[300px] w-full">
            <ResponsiveContainer>
              <PieChart>
                <Pie data={protocols} cx="50%" cy="50%" innerRadius={70} outerRadius={100} paddingAngle={5} dataKey="value" stroke="none" isAnimationActive={false}>
                  {protocols.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <RechartsTooltip content={<CustomTooltip />} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </BentoBox>
      </div>

      {/* Timeline */}
      <BentoBox delay={0.7}>
        <BentoHeader title="Live Timeline" icon={TrendingUp} colorClasses="text-cyber-accent" tooltip="Time-series of traffic volume & anomaly detections." />
        <div className="h-[320px] w-full">
          <ResponsiveContainer>
            <ComposedChart data={formattedData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorVol" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#00d4ff" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="timeLabel" stroke="#a8b8d4" tick={{ fontSize: 11 }} minTickGap={30} />
              <YAxis yAxisId="left" stroke="#a8b8d4" tick={{ fontSize: 11 }} />
              <YAxis yAxisId="right" orientation="right" stroke="#a8b8d4" tick={{ fontSize: 11 }} domain={[-1, 1]} />
              <RechartsTooltip content={<CustomTooltip />} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Area yAxisId="left" type="monotone" dataKey="bytes_sent" name="Traffic Vol" stroke="#00d4ff" fillOpacity={1} fill="url(#colorVol)" animationDuration={500} />
              <Line yAxisId="right" type="step" dataKey="anomaly_score" name="Threat Score" stroke="#ff0055" strokeDasharray="5 5" dot={false} isAnimationActive={false} />
              <Scatter yAxisId="left" dataKey="bytes_sent" name="Anomalies" fill="#ff0055" shape="wye" data={scatterAnomaly} isAnimationActive={false}/>
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </BentoBox>

      {/* Row 4: Deep Dive */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Anomaly Score Histogram / Distribution Approximation */}
        <BentoBox delay={0.8}>
          <BentoHeader title="Scores Trend" icon={Target} colorClasses="text-cyber-warning" tooltip="Recent isolation forest scores. Lower = higher threat." />
          <div className="h-[280px] w-full">
            <ResponsiveContainer>
              <BarChart data={formattedData.slice(-50)} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="timeLabel" stroke="#a8b8d4" tick={{ fontSize: 11 }} minTickGap={20} />
                <YAxis stroke="#a8b8d4" tick={{ fontSize: 11 }} domain={[-0.5, 0.2]} />
                <RechartsTooltip content={<CustomTooltip />} />
                <ReferenceLine y={threshold} stroke="#ff0055" strokeDasharray="3 3" label={{ position: 'insideTopLeft', value: 'Threshold', fill: '#ff0055', fontSize: 11 }} />
                <Bar dataKey="anomaly_score" fill="#ffa500" opacity={0.8} radius={[4, 4, 0, 0]} isAnimationActive={false}>
                  {formattedData.slice(-50).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.anomaly_score < threshold ? '#ff0055' : '#ffa500'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </BentoBox>

        {/* Explainable Insights */}
        <BentoBox delay={0.9} className="h-full">
          <BentoHeader title="Explainable Insights" icon={Brain} colorClasses="text-cyber-accent" tooltip="Contextual breakdown of the current environment." />
          <div className="flex-1 flex flex-col justify-center px-4">
            <span className="insight-line"><span className="insight-num">1)</span> Threat Level: <span className="insight-val">{threatRate.toFixed(2)}%</span> of recent traffic is anomalous.</span>
            <span className="insight-line"><span className="insight-num">2)</span> Dominant Protocol: <span className="insight-val">{protocols.length ? protocols[0].name : "N/A"}</span></span>
            <span className="insight-line"><span className="insight-num">3)</span> Avg Packet Count: <span className="insight-val">{pktMean.toFixed(1)}</span> per event.</span>
            <span className="insight-line"><span className="insight-num">4)</span> Anomaly Score: current: <span className="insight-val">{latestScore.toFixed(3)}</span> | avg: <span className="insight-val">{avgScore.toFixed(3)}</span></span>
            <span className="insight-line"><span className="insight-num">5)</span> Last Updated: <span className="insight-val">{new Date(stats.last_updated).toLocaleTimeString()}</span></span>
            
            <span className="block mt-6 text-[#a8b8d4] italic text-xs leading-relaxed">
              Outlier points and red markers deeply indicate suspicious traffic spikes requiring manual review. Ensure network isolation if threat score persists below threshold.
            </span>
          </div>
        </BentoBox>
      </div>
    </div>
  );
}
